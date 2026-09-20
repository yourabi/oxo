# frozen_string_literal: true

require "connection_pool"
require "securerandom"
require "timeout"

module Oxo
  module PressureFixture
    class RedisUnavailable < StandardError; end

    SimulatedConnection = Struct.new(:kind, :id, :operations, keyword_init: true) do
      def execute(hold_ms:)
        sleep(hold_ms.to_i / 1000.0) if hold_ms.to_i.positive?
        self.operations += 1
      end
    end

    module_function

    def db_probe(hold_ms:)
      return external_db_probe(hold_ms: hold_ms) if external_pressure?

      with_pool(:db, db_pool, hold_ms)
    rescue ConnectionPool::TimeoutError
      failure(:db, "db_pool_exhausted", db_pool_size)
    end

    def db_hold(hold_ms:)
      db_probe(hold_ms: hold_ms)
    end

    def redis_probe(hold_ms:)
      return external_redis_probe(hold_ms: hold_ms) if external_pressure?

      ensure_redis_available!
      with_pool(:redis, redis_pool, hold_ms)
    rescue RedisUnavailable
      failure(:redis, "redis_unavailable", redis_pool_size)
    rescue ConnectionPool::TimeoutError
      failure(:redis, "redis_pool_exhausted", redis_pool_size)
    end

    def redis_broadcast!(channel:, payload_bytes:)
      return external_redis_broadcast!(channel: channel, payload_bytes: payload_bytes) if external_pressure?

      ensure_redis_available!
      redis_pool.with do |connection|
        connection.execute(hold_ms: 0)
        {
          kind: "redis",
          adapter: cable_adapter_label,
          channel: channel,
          payload_bytes: payload_bytes,
          connection_id: connection.id
        }
      end
    rescue ConnectionPool::TimeoutError
      raise RedisUnavailable, "redis fixture pool exhausted"
    end

    def redis_available?
      return external_redis_available? if external_pressure?

      path = ENV["OXO_REDIS_FIXTURE_STATE"]
      return true if path.nil? || path.empty?

      File.read(path).strip != "down"
    rescue Errno::ENOENT
      true
    end

    def ensure_redis_available!
      return if redis_available?

      raise RedisUnavailable, "redis fixture unavailable"
    end

    def pool_status
      {
        tier: external_pressure? ? "external" : "local",
        db_pool_size: db_pool_size,
        db_timeout_ms: db_timeout_ms,
        redis_pool_size: redis_pool_size,
        redis_timeout_ms: redis_timeout_ms,
        redis_available: redis_available?,
        cable_adapter: cable_adapter_label
      }
    end

    def cable_adapter_label
      return "redis" if external_pressure? && ENV.fetch("OXO_CABLE_ADAPTER", "redis") == "redis"

      ENV.fetch("OXO_CABLE_ADAPTER", "async") == "oxo_file_bus" ? "file-bus" : "async"
    end

    def external_pressure?
      ENV["RAILS_ENV"] == "production_external"
    end

    def db_pool
      @db_pool ||= build_pool(:db, db_pool_size, db_timeout_ms)
    end

    def redis_pool
      @redis_pool ||= build_pool(:redis, redis_pool_size, redis_timeout_ms)
    end

    def build_pool(kind, size, timeout_ms)
      ConnectionPool.new(size: size, timeout: timeout_ms / 1000.0) do
        SimulatedConnection.new(kind: kind.to_s, id: SecureRandom.hex(4), operations: 0)
      end
    end
    private_class_method :build_pool

    def with_pool(kind, pool, hold_ms)
      started = monotonic_ms
      pool.with do |connection|
        waited_ms = monotonic_ms - started
        connection.execute(hold_ms: acknowledge_hold(hold_ms) ? 0 : hold_ms)
        {
          status: 200,
          body: {
            kind: kind.to_s,
            degraded: false,
            pool_size: kind == :db ? db_pool_size : redis_pool_size,
            waited_ms: waited_ms,
            held_ms: hold_ms.to_i,
            connection_id: connection.id,
            operations: connection.operations
          }
        }
      end
    end
    private_class_method :with_pool

    # A test observes this only AFTER checkout succeeds, then holds the pool
    # until its saturation request has received the expected response.
    def acknowledge_hold(hold_ms)
      return false unless hold_ms.to_i.positive? && ENV["OXO_TEST_POOL_ENTERED"]

      File.write(ENV.fetch("OXO_TEST_POOL_ENTERED"), "checked-out")
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      until File.exist?(ENV.fetch("OXO_TEST_POOL_RELEASE"))
        raise "pool release timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.01
      end
      true
    end
    private_class_method :acknowledge_hold

    def external_db_probe(hold_ms:)
      started = monotonic_ms
      ActiveRecord::Base.connection_pool.with_connection do |connection|
        waited_ms = monotonic_ms - started
        seconds = acknowledge_hold(hold_ms) ? 0 : hold_ms.to_i / 1000.0
        if seconds.positive?
          connection.execute("SELECT pg_sleep(#{seconds})")
        else
          connection.execute("SELECT 1")
        end
        {
          status: 200,
          body: {
            kind: "db",
            tier: "external",
            degraded: false,
            pool_size: db_pool_size,
            waited_ms: waited_ms,
            held_ms: hold_ms.to_i
          }
        }
      end
    rescue ActiveRecord::ConnectionTimeoutError
      failure(:db, "db_pool_exhausted", db_pool_size)
    rescue ActiveRecord::ActiveRecordError, PG::Error, Timeout::Error
      failure(:db, "db_unavailable", db_pool_size)
    end
    private_class_method :external_db_probe

    def external_redis_probe(hold_ms:)
      started = monotonic_ms
      redis_client do |client|
        waited_ms = monotonic_ms - started
        sleep(hold_ms.to_i / 1000.0) if hold_ms.to_i.positive?
        pong = client.ping
        {
          status: 200,
          body: {
            kind: "redis",
            tier: "external",
            degraded: false,
            pool_size: redis_pool_size,
            waited_ms: waited_ms,
            held_ms: hold_ms.to_i,
            response: pong
          }
        }
      end
    rescue Redis::BaseError, RedisUnavailable, Timeout::Error
      failure(:redis, "redis_unavailable", redis_pool_size)
    rescue ConnectionPool::TimeoutError
      failure(:redis, "redis_pool_exhausted", redis_pool_size)
    end
    private_class_method :external_redis_probe

    def external_redis_broadcast!(channel:, payload_bytes:)
      redis_client do |client|
        client.ping
        {
          kind: "redis",
          adapter: cable_adapter_label,
          channel: channel,
          payload_bytes: payload_bytes,
          connection_id: "external"
        }
      end
    rescue Redis::BaseError, ConnectionPool::TimeoutError
      raise RedisUnavailable, "external redis unavailable"
    end
    private_class_method :external_redis_broadcast!

    def external_redis_available?
      redis_client { |client| client.ping == "PONG" }
    rescue Redis::BaseError, ConnectionPool::TimeoutError
      false
    end
    private_class_method :external_redis_available?

    def redis_client(&block)
      external_redis_pool.with(&block)
    end
    private_class_method :redis_client

    def external_redis_pool
      @external_redis_pool ||= ConnectionPool.new(size: redis_pool_size, timeout: redis_timeout_ms / 1000.0) do
        Redis.new(
          url: ENV.fetch("REDIS_URL"),
          connect_timeout: redis_timeout_ms / 1000.0,
          read_timeout: redis_timeout_ms / 1000.0,
          write_timeout: redis_timeout_ms / 1000.0
        )
      end
    end
    private_class_method :external_redis_pool

    def failure(kind, reason, pool_size)
      {
        status: 503,
        body: {
          kind: kind.to_s,
          degraded: true,
          reason: reason,
          pool_size: pool_size
        }
      }
    end
    private_class_method :failure

    def db_pool_size
      integer_env("OXO_DB_POOL_SIZE", 2)
    end

    def db_timeout_ms
      integer_env("OXO_DB_POOL_TIMEOUT_MS", 250)
    end

    def redis_pool_size
      integer_env("OXO_REDIS_POOL_SIZE", 2)
    end

    def redis_timeout_ms
      integer_env("OXO_REDIS_POOL_TIMEOUT_MS", 250)
    end

    def integer_env(name, default)
      value = ENV.fetch(name, default).to_i
      value.positive? ? value : default
    end
    private_class_method :integer_env

    def monotonic_ms
      (Process.clock_gettime(Process::CLOCK_MONOTONIC) * 1000).round
    end
    private_class_method :monotonic_ms
  end
end
