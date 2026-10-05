# frozen_string_literal: true
# Independent frame bytes exercise the real async worker, including malformed
# framing, exactly-once errors, buffer reuse, binary headers and Rack::Lint.
require_relative "support"
Conformance.clean_environment!

require "async"
require "socket"
require "tmpdir"
require "json"
require "fileutils"

WORKER = File.expand_path("../../ruby/oxo_async_worker.rb", __dir__)
load WORKER # defines OxoAsync + handle_conn (main guarded by $PROGRAM_NAME)
OxoOrder.install_counters! # same initialization as the production server entrypoint

$failures = 0
$checks = 0
def check(name, cond, detail = nil)
  $checks += 1
  if cond
    puts "ok: #{name}"
  else
    $failures += 1
    puts "FAIL: #{name}#{detail ? " -- #{detail}" : ""}"
  end
end

TMP = Dir.mktmpdir("oxo-conformance")
at_exit { FileUtils.remove_entry_secure(TMP) if File.directory?(TMP) }
$invocations = 0

def install_app(name, ru_source)
  path = File.join(TMP, name)
  File.write(path, ru_source)
  OxoAsync.load_app(path)
end

COUNTING_OK = <<~RU
  run ->(env) { $invocations += 1; [200, { "content-type" => "text/plain" }, ["counted-ok"]] }
RU
COUNTING_RAISE = <<~RU
  run ->(env) { $invocations += 1; raise "app exploded on purpose" }
RU
BAD_STATUS = <<~RU
  run ->(env) { $invocations += 1; ["not-a-status", {}, ["x"]] }
RU
SLOW_OK = <<~RU
  run ->(env) { $invocations += 1; sleep 0.3; [200, { "content-type" => "text/plain" }, ["slow-ok"]] }
RU

def simple_frame(path = "/t", query = "")
  enc_short = ->(s) { [s.bytesize].pack("v") + s.b }
  enc_long = ->(s) { [s.bytesize].pack("V") + s.b }
  env = +"".b
  env << enc_short.call("GET") << enc_long.call(path) << enc_long.call(query)
  env << enc_short.call("localhost") << [80].pack("v") << [0].pack("C")
  env << enc_short.call("127.0.0.1") << [1].pack("v")
  env << enc_short.call("host") << enc_long.call("localhost")
  env << [0].pack("V")
  [0xBF, 0x01].pack("C2") + [env.bytesize].pack("V") + env
end

def read_response(io)
  prefix = io.read(6)
  return nil if prefix.nil? || prefix.bytesize < 6
  env = io.read(prefix.byteslice(2, 4).unpack1("V"))
  status = env.byteslice(1, 2).unpack1("v")
  [status, env]
end

install_app("counting_ok.ru", COUNTING_OK)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  frame = simple_frame
  $invocations = 0
  seen_early = false
  frame.each_byte.with_index do |byte, i|
    last = i == frame.bytesize - 1
    a.write(byte.chr)
    a.flush
    sleep 0.005 # a real reactor turn between bytes — the worker's read fiber runs
    seen_early ||= ($invocations != 0 && !last)
  end
  read_status, = read_response(a)
  check("partial frame does not invoke the application", !seen_early)
  check("complete frame invokes the application exactly once", $invocations == 1)
  status = read_status
  check("byte-at-a-time request receives a 200 response", status == 200)
  a.close
end

def decode_error_case(task, label, bytes)
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  $invocations = 0
  a.write(bytes)
  a.flush
  a.close_write if a.respond_to?(:close_write)
  got = begin
    a.read # nil/"" on close with nothing written
  rescue Errno::ECONNRESET
    "" # Reset with unread request data; no response bytes were received.
  end
  check("#{label}: connection closes without response bytes", got.nil? || got.empty?)
  check("#{label}: application is not invoked", $invocations.zero?)
  a.close
rescue StandardError => e
  check("#{label}: malformed-frame check completes", false, "#{e.class}: #{e.message}")
end

Async do |task|
  decode_error_case(task, "bad-magic", "\xAA\x01\x10\x00\x00\x00".b + ("x" * 16).b)
  decode_error_case(task, "oversized-declared-length", [0xBF, 0x01].pack("C2") + [999_999_999].pack("V"))
  good = simple_frame
  decode_error_case(task, "truncated-envelope", good.byteslice(0, good.bytesize - 5))
  decode_error_case(task, "malformed-envelope", [0xBF, 0x01].pack("C2") + [24].pack("V") + ("\xFF".b * 24))
end

install_app("counting_raise.ru", COUNTING_RAISE)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  $invocations = 0
  a.write(simple_frame)
  a.flush
  status, = read_response(a)
  check("application exception produces a 500 error frame", status == 500)
  check("application exception is not replayed", $invocations == 1)
  after = a.read # EOF must follow the error frame.
  check("connection closes after the error frame", after.nil? || after.empty?)
  a.close
end

install_app("bad_status.ru", BAD_STATUS)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  $invocations = 0
  a.write(simple_frame)
  a.flush
  status, = read_response(a)
  check("invalid application status produces a 500 error frame", status == 500)
  a.close
end

install_app("slow_ok.ru", SLOW_OK)
Async do |task|
  a, b = UNIXSocket.pair
  done = false
  handler = task.async do
    handle_conn(b)
    done = true
  end
  $invocations = 0
  a.write(simple_frame)
  a.flush
  a.close # reader gone before the 0.3s app finishes
  handler.wait
  check("failed response write closes the connection and returns from the handler", done)
  check("failed response write does not replay the application", $invocations == 1)
end

install_app("counting_ok2.ru", COUNTING_OK)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  sleep 1.5 # idle: the worker must NOT time out (only the edge retires idles)
  a.write(simple_frame)
  a.flush
  status, = read_response(a)
  check("connection serves a request after 1.5 seconds idle", status == 200)
  a.close
end

lint_ru = File.join(TMP, "lint_ok.ru")
File.write(lint_ru, COUNTING_OK)
OxoAsync.load_app(lint_ru, lint: true)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  a.write(simple_frame("/lint", "q=1"))
  a.flush
  status, = read_response(a)
  check("request environment passes Rack::Lint", status == 200)
  a.close
end



def frame_with_headers(path, headers, body = "".b)
  enc_short = ->(s) { [s.bytesize].pack("v") + s.b }
  enc_long = ->(s) { [s.bytesize].pack("V") + s.b }
  env = +"".b
  env << enc_short.call("GET") << enc_long.call(path) << enc_long.call("")
  env << enc_short.call("localhost") << [80].pack("v") << [0].pack("C")
  env << enc_short.call("127.0.0.1") << [headers.length].pack("v")
  headers.each { |k, v| env << enc_short.call(k) << enc_long.call(v) }
  env << [body.bytesize].pack("V") << body
  [0xBF, 0x01].pack("C2") + [env.bytesize].pack("V") + env
end

def parse_response(env)
  status = env.byteslice(1, 2).unpack1("v")
  count = env.byteslice(3, 2).unpack1("v")
  pos = 5
  headers = []
  count.times do
    nlen = env.byteslice(pos, 2).unpack1("v"); pos += 2
    name = env.byteslice(pos, nlen); pos += nlen
    vlen = env.byteslice(pos, 4).unpack1("V"); pos += 4
    value = env.byteslice(pos, vlen); pos += vlen
    headers << [name, value]
  end
  blen = env.byteslice(pos, 4).unpack1("V"); pos += 4
  [status, headers, env.byteslice(pos, blen)]
end

ECHO_KEYS = <<~RU
  run ->(env) {
    keys = env.keys.select { |k| k.start_with?("HTTP_") || %w[CONTENT_LENGTH CONTENT_TYPE].include?(k) }.sort
    [200, { "content-type" => "text/plain" }, [keys.join(",")]]
  }
RU
install_app("echo_keys.ru", ECHO_KEYS)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  a.write(frame_with_headers("/hk", [
    ["X-Forwarded-For", "1.2.3.4"], ["X-Oxo-Secret", "x"], ["X-Oxo-Ts0", "123"], ["Connection", "close"],
    ["X-Custom-Thing", "v"], ["Content-Length", "0"], ["Host", "h"]
  ]))
  a.flush
  _, _, body = parse_response(read_response(a)[1])
  check("mixed-case reserved headers are removed and allowed headers reach Rack",
        body == "CONTENT_LENGTH,HTTP_HOST,HTTP_X_CUSTOM_THING", body.inspect)
  a.close
end

ENC_HEADERS = <<~'RU'
  run ->(env) {
    h = {
      "content-type" => "text/plain",
      "x-plain" => "ok".freeze,
      "x-utf8" => "caf\u00e9".freeze,
      "x-bad-utf8" => (+"\xFF").force_encoding(Encoding::UTF_8).freeze,
      "x-bin" => "\x80\xFF".b.freeze,
      "x-ctl" => "bad\x01".freeze,
      "x-empty" => ""
    }
    [200, h, ["enc-ok"]]
  }
RU
install_app("enc_headers.ru", ENC_HEADERS)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  a.write(frame_with_headers("/enc", [["Host", "h"]]))
  a.flush
  resp = read_response(a)
  status, headers, body = resp ? parse_response(resp[1]) : [nil, [], ""]
  names = headers.map(&:first)
  check("frozen non-ASCII header values encode successfully",
        status == 200 && body == "enc-ok", "status=#{status.inspect}")
  check("UTF-8, invalid UTF-8, binary and empty header values are retained",
        %w[x-utf8 x-bad-utf8 x-bin x-empty].all? { |n| names.include?(n) }, names.inspect)
  check("header value containing a control byte is removed", !names.include?("x-ctl"), names.inspect)
  a.close
end

PATH_ECHO = <<~RU
  run ->(env) { [200, { "content-type" => "text/plain", "x-path" => env["PATH_INFO"] }, [env["PATH_INFO"] * 5]] }
RU
install_app("path_echo.ru", PATH_ECHO)
Async do |task|
  a, b = UNIXSocket.pair
  task.async { handle_conn(b) }
  a.write(frame_with_headers("/aaaaaaaa", [["Host", "h"]])); a.flush
  _, h1, b1 = parse_response(read_response(a)[1])
  check("long response correct", b1 == "/aaaaaaaa" * 5 && h1.include?(["x-path", "/aaaaaaaa"]))
  a.write(frame_with_headers("/bb", [["Host", "h"]])); a.flush
  _, h2, b2 = parse_response(read_response(a)[1])
  check("shorter second response byte-clean (no residue from the reused buffer)",
        b2 == "/bb" * 5 && h2.include?(["x-path", "/bb"]) && !b2.include?("aaaa"), b2.inspect)
  got_extra = nil
  begin
    a.read_nonblock(64)
    got_extra = true
  rescue IO::WaitReadable, EOFError
    got_extra = false
  end
  check("no trailing bytes after the reused-buffer frame", got_extra == false)
  a.close
end

SLOW_FAST = <<~RU
  run ->(env) {
    if env["PATH_INFO"] == "/slow"
      $slow_entered = true
      sleep 0.01 until $slow_release
      [200, { "content-type" => "text/plain" }, ["slow-done"]]
    else
      [200, { "content-type" => "text/plain", "x-fast" => "1" }, [env["PATH_INFO"] * 3]]
    end
  }
RU
install_app("slow_fast.ru", SLOW_FAST)
$slow_entered = false
$slow_release = false
Async do |task|
  reg = ConnRegistry.new
  a, wa = UNIXSocket.pair
  c, wc = UNIXSocket.pair
  task.async { handle_conn(wa, reg) }
  task.async { handle_conn(wc, reg) }
  a.write(frame_with_headers("/slow", [["Host", "h"]])); a.flush
  task.with_timeout(5) { sleep 0.01 until $slow_entered }
  ok_b = true
  2.times do |i|
    c.write(frame_with_headers("/f#{i}", [["Host", "h"]])); c.flush
    _, _, fb = parse_response(read_response(c)[1])
    ok_b &&= (fb == "/f#{i}" * 3)
  end
  check("second connection returns correct bytes while the first application request waits", ok_b)
  reg.abandon_in_flight!
  raw = +"".b
  begin
    loop do
      chunk = a.read_nonblock(4096)
      break if chunk.nil?
      raw << chunk
    end
  rescue EOFError, IO::WaitReadable, Errno::ECONNRESET
    nil
  end
  expected = OxoAsync.encode_error_frame
  check("drain sends the expected 500 error frame",
        raw.start_with?(expected), "got #{raw.bytesize} bytes")
  $slow_release = true
  a.close; c.close
end

install_app("path_echo2.ru", PATH_ECHO)
Async do |task|
  a, b = UNIXSocket.pair
  done = false
  handler = task.async { handle_conn(b); done = true }
  a.write(frame_with_headers("/x", [["Host", "h"]])); a.flush
  read_response(a)
  a.close # EOF exactly at a frame boundary
  handler.wait
  check("clean EOF at a frame boundary after a completed request", done)
end
Async do |task|
  a, b = UNIXSocket.pair
  done = false
  handler = task.async { handle_conn(b); done = true }
  a.write(frame_with_headers("/y", [["Host", "h"]])); a.flush
  read_response(a)
  a.write("\xBF\x01\x03".b); a.flush # 3 bytes of a prefix, then EOF mid-frame
  a.close_write
  handler.wait
  extra = begin
    a.read
  rescue Errno::ECONNRESET
    ""
  end
  check("mid-prefix EOF after a completed request closes with no extra bytes",
        done && (extra.nil? || extra.empty?))
  a.close
end



EXPECTED_CHECKS = 30
if $checks != EXPECTED_CHECKS
  $failures += 1
  puts "FAIL: only #{$checks}/#{EXPECTED_CHECKS} checks executed"
end
puts "ASYNC PROTOCOL: #{$checks} checks, #{$failures} failures"
exit($failures.zero? ? 0 : 1)
