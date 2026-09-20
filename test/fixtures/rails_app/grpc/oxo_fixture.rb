# frozen_string_literal: true

# JSON messages and unary/streaming RPCs for the supervised Rails/gruf sidecar.
require "json"
require "grpc"
require "gruf"

module OxoGrpc
  class JsonMessage
    attr_reader :fields

    def initialize(fields = {})
      @fields = fields.transform_keys(&:to_s)
    end

    def [](key)
      fields[key.to_s]
    end

    def self.marshal(message)
      JSON.generate(message.fields)
    end

    def self.unmarshal(bytes)
      new(JSON.parse(bytes))
    end
  end

  class PingRequest < JsonMessage; end

  class PingReply < JsonMessage; end

  class FixtureService
    include GRPC::GenericService

    self.marshal_class_method = :marshal
    self.unmarshal_class_method = :unmarshal
    self.service_name = "oxo.fixture.Fixture"

    rpc :Ping, PingRequest, PingReply
    rpc :StreamPings, PingRequest, stream(PingReply)
    rpc :CollectPings, stream(PingRequest), PingReply
    rpc :BidiPings, stream(PingRequest), stream(PingReply)
  end

  class FixtureController < Gruf::Controllers::Base
    bind FixtureService

    def ping
      message = request.message["message"].to_s
      if message == "invalid"
        raise GRPC::BadStatus.new(GRPC::Core::StatusCodes::INVALID_ARGUMENT, "oxo invalid")
      end
      if message.start_with?("sleep:")
        sleep(Float(message.delete_prefix("sleep:")) / 1000.0)
      end

      PingReply.new(
        message: "pong:#{message}",
        rails_env: Rails.env,
        metadata: request.metadata.fetch("x-oxo-test", ""),
        edge_server_name: request.metadata.fetch("x-oxo-server-name", ""),
        spoofed_forwarded_for: request.metadata.fetch("x-forwarded-for", ""),
        request_id: request.metadata.fetch("x-oxo-request-id", ""),
        service: request.service.name
      )
    end

    def stream_pings
      message = request.message
      count = integer_field(message, "count", 3)
      delay_ms = integer_field(message, "delay_ms", 0)

      Enumerator.new do |out|
        count.times do |index|
          out << reply_for(message, "stream:#{index}:#{message['message']}")
          sleep(delay_ms / 1000.0) if delay_ms.positive?
        end
      end
    end

    def collect_pings
      labels = []
      first = nil
      index = 0
      request.messages do |message|
        first ||= message
        labels << "#{index}:#{message['message']}"
        index += 1
      end

      reply_for(first || PingRequest.new, "collect:#{labels.join('|')}")
    end

    def bidi_pings
      Enumerator.new do |out|
        request.messages.each_with_index do |message, index|
          out << reply_for(message, "bidi:#{index}:#{message['message']}")
        end
      end
    end

    private

    def reply_for(message, label)
      PingReply.new(
        message: label,
        rails_env: Rails.env,
        metadata: request.metadata.fetch("x-oxo-test", ""),
        edge_server_name: request.metadata.fetch("x-oxo-server-name", ""),
        spoofed_forwarded_for: request.metadata.fetch("x-forwarded-for", ""),
        request_id: request.metadata.fetch("x-oxo-request-id", ""),
        service: request.service.name,
        payload: "x" * integer_field(message, "payload_bytes", 0)
      )
    end

    def integer_field(message, key, default)
      Integer(message[key] || default)
    rescue ArgumentError, TypeError
      default
    end
  end
end
