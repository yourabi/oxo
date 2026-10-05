# frozen_string_literal: true

require "oxo/pressure_fixture"

module Oxo
  # Closes every Action Cable connection once the pub/sub backend stops answering, so
  # clients reconnect instead of holding sessions no broadcast can reach. The stock
  # Redis adapter only abandons its listener when the connection is lost; the open
  # websockets keep receiving pings and nothing else.
  module CableBackendMonitor
    INTERVAL_SECONDS = 0.25

    @mutex = Mutex.new
    @thread = nil

    module_function

    def start
      return unless ENV["OXO_CABLE_ADAPTER"] == "redis"

      @mutex.synchronize do
        return if @thread&.alive?

        @thread = Thread.new { run }
        @thread.name = "oxo-cable-backend-monitor"
      end
    end

    def run
      reachable = true
      loop do
        now_reachable = Oxo::PressureFixture.redis_available?
        if reachable && !now_reachable
          ActionCable.server.connections.each do |connection|
            connection.close(reason: "pubsub_backend_unreachable", reconnect: true)
          end
        end
        reachable = now_reachable
        sleep INTERVAL_SECONDS
      end
    end
    private_class_method :run
  end
end
