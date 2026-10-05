# This is a synthetic file-backed fanout bus, not a Redis adapter.
# frozen_string_literal: true

require "action_cable/subscription_adapter/inline"
require "oxo/pressure_fixture"
require "fileutils"
require "json"
require "securerandom"

module ActionCable
  module SubscriptionAdapter
    class OxoFileBus < Inline
      def broadcast(channel, payload)
        Oxo::PressureFixture.redis_broadcast!(channel: channel, payload_bytes: payload.bytesize)
        publish_to_bus(channel, payload) if bus_path
        super
      rescue Oxo::PressureFixture::RedisUnavailable => e
        logger.error("oxo redis fixture broadcast unavailable: #{e.message}") if logger
        raise
      end

      def shutdown
        subscriber_map.shutdown if subscriber_map.respond_to?(:shutdown)
      end

      private

      def new_subscriber_map
        if bus_path
          OxoFileBusSubscriberMap.new(server.event_loop, bus_path)
        else
          super
        end
      end

      def bus_path
        path = ENV["OXO_REDIS_FIXTURE_BUS"]
        path if path && !path.empty?
      end

      def publish_to_bus(channel, payload)
        event = {
          id: SecureRandom.hex(12),
          pid: Process.pid,
          channel: channel,
          payload: payload
        }
        FileUtils.mkdir_p(File.dirname(bus_path))
        File.open(bus_path, File::WRONLY | File::APPEND | File::CREAT, 0o600) do |file|
          file.flock(File::LOCK_EX)
          file.puts(JSON.generate(event))
        ensure
          file.flock(File::LOCK_UN) if file
        end
      end

      class OxoFileBusSubscriberMap < SubscriberMap
        POLL_INTERVAL = 0.05

        def initialize(event_loop, bus_path)
          @event_loop = event_loop
          @bus_path = bus_path
          @shutdown = false
          FileUtils.mkdir_p(File.dirname(@bus_path))
          FileUtils.touch(@bus_path)
          @position = File.size(@bus_path)
          super()
          @thread = Thread.new { poll_bus }
        end

        def add_subscriber(*)
          @event_loop.post { super }
        end

        def invoke_callback(*)
          @event_loop.post { super }
        end

        def shutdown
          @shutdown = true
          @thread&.join(1)
        end

        private

        def poll_bus
          until @shutdown
            read_new_events
            sleep POLL_INTERVAL
          end
        end

        def read_new_events
          File.open(@bus_path, File::RDONLY) do |file|
            file.flock(File::LOCK_SH)
            file.seek(@position)
            file.each_line do |line|
              @position = file.pos
              event = JSON.parse(line)
              next if event["pid"] == Process.pid

              broadcast(event.fetch("channel"), event.fetch("payload"))
            rescue JSON::ParserError, KeyError
              next
            end
          end
        rescue Errno::ENOENT
          FileUtils.touch(@bus_path)
          @position = 0
        end
      end
    end
  end
end
