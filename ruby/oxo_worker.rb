# frozen_string_literal: true
#
# oxo_worker.rb - legacy -supervised TCP worker helper.
#
# This file belongs to the historical hyper/Puma-era reference path, not the
# current Linux S1 Magnus UDS worker and not the Pingora RC path. It remains
# useful for legacy tests because it is deliberately minimal and strict: one
# Content-Length-framed HTTP request per connection, ambiguous framing rejected,
# a per-worker shared secret gate, and Connection: close.
#
# Do not modernize this comment into a UDS/Pingora claim. Current behavior lives
# in `crates/oxo-worker` and `crates/oxo-pingora-edge`.

require "socket"
require "stringio"
require "rack"

SECRET = ENV.fetch("OXO_WORKER_SECRET")
APP_PATH = ENV.fetch("OXO_WORKER_APP")
MAX_BODY = Integer(ENV.fetch("OXO_WORKER_MAX_BODY", "1048576"), 10)
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 100

# Collector for Rack 3 "streaming" bodies that respond to #call(stream).
class StreamCollector
  def initialize
    @buf = +"".b
  end

  def write(chunk)
    s = chunk.to_s.b
    @buf << s
    s.bytesize
  end

  def <<(chunk)
    write(chunk)
    self
  end

  def flush
    self
  end

  def close; end

  def closed?
    false
  end

  def to_str
    @buf
  end
  alias to_s to_str
end

def secure_compare(a, b)
  return Rack::Utils.secure_compare(a, b) if Rack::Utils.respond_to?(:secure_compare)
  return false unless a.bytesize == b.bytesize

  res = 0
  a.each_byte.zip(b.each_byte) { |x, y| res |= (x ^ y) }
  res.zero?
end

def status_text(status)
  Rack::Utils::HTTP_STATUS_CODES.fetch(status, "Status")
end

# Consume a Rack response body supporting BOTH #each (Enumerable) and #call
# (streaming). Per the Rack SPEC, a body responding to both is treated as Enumerable,
# and #close must always be called.
def read_body(body)
  out = +"".b
  begin
    if body.respond_to?(:call) && !body.respond_to?(:each)
      collector = StreamCollector.new
      body.call(collector)
      out << collector.to_str
    else
      body.each { |part| out << part.to_s.b }
    end
  ensure
    body.close if body.respond_to?(:close)
  end
  out
end

def write_response(conn, status, headers, body)
  payload = read_body(body)
  out = +"HTTP/1.1 #{status} #{status_text(status)}\r\n"
  (headers || {}).each do |k, v|
    key = k.to_s
    next if %w[content-length transfer-encoding connection].include?(key.downcase)

    Array(v).each do |val|
      val.to_s.split("\n").each { |seg| out << "#{key}: #{seg}\r\n" }
    end
  end
  out << "content-length: #{payload.bytesize}\r\n"
  out << "connection: close\r\n"
  out << "\r\n"
  conn.write(out)
  conn.write(payload) unless payload.empty?
end

def simple_response(conn, status, text)
  write_response(conn, status, { "content-type" => "text/plain; charset=utf-8" }, [text])
end

def build_env(method, target, version, headers, body)
  path, _sep, query = target.partition("?")
  input = StringIO.new(body.dup)
  input.set_encoding(Encoding::BINARY) # rack.input must be ASCII-8BIT / binary, rewindable
  host = headers["host"].to_s
  env = {
    "REQUEST_METHOD" => method,
    "SCRIPT_NAME" => "",
    "PATH_INFO" => path,
    "QUERY_STRING" => query,
    "SERVER_NAME" => (host.split(":").first || ""),
    "SERVER_PORT" => (host.include?(":") ? host.split(":").last : ""),
    "SERVER_PROTOCOL" => (version || "HTTP/1.1"),
    "rack.url_scheme" => "http",
    "rack.input" => input,
    "rack.errors" => $stderr,
    "rack.multithread" => false,
    "rack.multiprocess" => true,
    "rack.run_once" => false,
  }
  env["CONTENT_LENGTH"] = headers["content-length"] if headers["content-length"]
  env["CONTENT_TYPE"] = headers["content-type"] if headers["content-type"]
  headers.each do |k, v|
    next if %w[content-length content-type host connection x-oxo-secret].include?(k)

    env["HTTP_#{k.upcase.tr('-', '_')}"] = v
  end
  env
end

def handle_connection(conn)
  request_line = conn.gets("\r\n")
  return simple_response(conn, 400, "empty request") if request_line.nil?

  method, target, version = request_line.chomp.split(" ", 3)
  return simple_response(conn, 400, "malformed request line") if method.nil? || target.nil?

  headers = {}
  total = 0
  count = 0
  loop do
    line = conn.gets("\r\n")
    return simple_response(conn, 400, "unterminated headers") if line.nil?
    break if line == "\r\n"

    total += line.bytesize
    count += 1
    return simple_response(conn, 431, "headers too large") if total > MAX_HEADER_BYTES
    return simple_response(conn, 431, "too many headers") if count > MAX_HEADERS
    return simple_response(conn, 400, "obsolete line folding") if line.start_with?(" ", "\t")

    name, value = line.chomp.split(":", 2)
    return simple_response(conn, 400, "malformed header") if name.nil? || value.nil?

    name = name.strip.downcase
    value = value.strip
    return simple_response(conn, 400, "transfer-encoding not allowed") if name == "transfer-encoding"
    return simple_response(conn, 400, "duplicate header") if headers.key?(name)

    headers[name] = value
  end

  provided = headers["x-oxo-secret"]
  return simple_response(conn, 403, "forbidden") unless provided && secure_compare(provided, SECRET)

  body = "".b
  if headers["content-length"]
    len = begin
      Integer(headers["content-length"], 10)
    rescue ArgumentError
      return simple_response(conn, 400, "bad content-length")
    end
    return simple_response(conn, 413, "payload too large") if len > MAX_BODY

    if len.positive?
      body = conn.read(len).to_s
      return simple_response(conn, 400, "short body") if body.bytesize < len
    end
  end

  status, resp_headers, resp_body = APP.call(build_env(method, target, version, headers, body))
  write_response(conn, Integer(status), resp_headers, resp_body)
rescue StandardError => e
  begin
    simple_response(conn, 500, "worker error: #{e.class}: #{e.message}")
  rescue StandardError
    nil
  end
end

# --- main ---------------------------------------------------------------------

# Test-only boot-failure hook (off in production): when OXO_TEST_FAIL_FILE names an
# existing file, crash at boot *before* the port handshake. The supervisor's respawn /
# crash-loop / stderr-tail paths are exercised by toggling that file's existence. The env
# var alone is inert (only the file's presence trips it), so it can't affect other workers.
fail_file = ENV["OXO_TEST_FAIL_FILE"]
if fail_file && !fail_file.empty? && File.exist?(fail_file)
  $stderr.puts("oxo worker: OXO_TEST_FAIL_FILE present (#{fail_file}); failing boot")
  $stderr.flush
  exit(1)
end

# Load the Rack app. Handle the Rack 2 ([app, options]) vs Rack 3 (app) return shape.
loaded = Rack::Builder.parse_file(APP_PATH)
APP = loaded.is_a?(Array) ? loaded.first : loaded

server = TCPServer.new("127.0.0.1", 0)
port = server.addr[1]
$stdout.sync = true
$stdout.puts("OXO_PORT=#{port}") # the handshake the parent reads
$stdout.flush

loop do
  conn = server.accept
  begin
    handle_connection(conn)
  ensure
    begin
      conn.close
    rescue StandardError
      nil
    end
  end
end
