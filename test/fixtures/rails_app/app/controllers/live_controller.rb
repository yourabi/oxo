class LiveController < ApplicationController
  include ActionController::Live

  def events
    response.headers["Content-Type"] = "text/event-stream"
    response.headers["Cache-Control"] = "no-cache"
    response.headers.delete("Content-Length")
    last_event_id = request.headers["Last-Event-ID"].presence || "none"
    response.stream.write "event: oxo\n"
    response.stream.write "id: #{last_event_id}\n"
    response.stream.write "data: one\n\n"
    response.stream.flush if response.stream.respond_to?(:flush)
    if (release = ENV["OXO_TEST_STREAM_RELEASE"])
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      until File.exist?(release)
        raise "stream release acknowledgement timed out" if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
        sleep 0.01
      end
    else
      sleep 0.8
    end
    response.stream.write "data: two\n\n"
  ensure
    response.stream.close
  end
end
