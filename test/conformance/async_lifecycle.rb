# frozen_string_literal: true
# Process-level READY, draining and socket ownership contracts.
require_relative "support"
Conformance.clean_environment!

require "socket"
require "tmpdir"
require "timeout"

WORKER = File.expand_path("../../ruby/oxo_async_worker.rb", __dir__)

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

FRAME_MAGIC = 0xBF
FRAME_VERSION = 0x01

def encode_request(path = "/t")
  env = +"".b
  short = ->(s) { [s.bytesize].pack("v") + s.b }
  long = ->(s) { [s.bytesize].pack("V") + s.b }
  env << short.call("GET") << long.call(path) << long.call("")
  env << short.call("conformance") << [45_678].pack("v") << [0].pack("C")
  env << short.call("127.0.0.1")
  env << [1].pack("v") << short.call("host") << long.call("conformance")
  env << long.call("") # empty body
  [FRAME_MAGIC, FRAME_VERSION].pack("C2") + [env.bytesize].pack("V") + env
end

def read_status(io, timeout_s = 10)
  Timeout.timeout(timeout_s) do
    prefix = io.read(6)
    return nil unless prefix && prefix.bytesize == 6
    remaining = prefix.byteslice(2, 4).unpack1("V")
    envelope = io.read(remaining)
    return nil unless envelope && envelope.bytesize == remaining
    envelope.byteslice(1, 2).unpack1("v")
  end
rescue Timeout::Error
  nil
end

def write_app(dir, name, source)
  path = File.join(dir, name)
  File.write(path, source)
  path
end

TRIVIAL = <<~RU
  run ->(env) { [200, { "content-type" => "text/plain" }, ["ok"]] }
RU
SLOW300 = <<~RU
  run ->(env) { File.write(ENV.fetch("OXO_TEST_ENTERED"), "entered"); sleep 0.01 until File.exist?(ENV.fetch("OXO_TEST_RELEASE")); [200, { "content-type" => "text/plain" }, ["slow-ok"]] }
RU
SLOW3000 = <<~RU
  run ->(env) { File.write(ENV.fetch("OXO_TEST_ENTERED"), "entered"); deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 3; sleep 0.01 until File.exist?(ENV.fetch("OXO_TEST_RELEASE")) || Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline; [200, { "content-type" => "text/plain" }, ["very-slow"]] }
RU
SLOW_BOOT = <<~RU
  File.write(ENV.fetch("OXO_TEST_ENTERED"), "boot-entered")
  sleep 30
  run ->(env) { [200, {}, ["never"]] }
RU

require_relative "worker"

def with_worker(app_source, extra_env = {})
  Dir.mktmpdir("oxo-lifecycle") do |dir|
    File.chmod(0o700, dir)
    app = write_app(dir, "app.ru", app_source)
    w = WorkerProc.new(dir, app, extra_env)
    begin
      yield w
    ensure
      w.reap!
    end
  end
end

with_worker(TRIVIAL) do |w|
  line, = w.await_ready
  check("worker emits the expected readiness line", line == "OXO_WORKER_READY=#{w.socket}\n",
        line.inspect)
  conn = w.connect
  conn.write(encode_request)
  check("worker serves requests after readiness", read_status(conn) == 200)
  statuses = 20.times.map { conn.write(encode_request); read_status(conn) }
  check("twenty sequential requests reuse the same connection", statuses == [200] * 20)
  conn.close
  extra = w.stdout_r.read_nonblock(4096, exception: false)
  check("stdout contains only the readiness line", extra == :wait_readable, extra.inspect)
end

with_worker(SLOW300) do |w|
  w.await_ready
  conn = w.connect
  conn.write(encode_request)
  w.await_entered
  w.term
  w.release
  status = read_status(conn)
  check("in-flight response completes during shutdown", status == 200, status.inspect)
  st = w.wait_exit
  check("worker exits successfully after draining", st&.exitstatus == 0, st.inspect)
  check("clean drain emits no deadline-expiry diagnostic",
        !w.stderr_text.include?("drain_deadline_expired"))
end

with_worker(TRIVIAL) do |w|
  w.await_ready
  conn = w.connect
  conn.write(encode_request)
  check("worker serves a request before draining", read_status(conn) == 200)
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  w.term
  st = w.wait_exit
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  check("idle connections do not delay shutdown", st&.exitstatus == 0 && elapsed < 2.0,
        "st=#{st.inspect} elapsed=#{elapsed.round(3)}s")
  conn.close
end

Dir.mktmpdir("oxo-lifecycle-boot") do |dir|
  File.chmod(0o700, dir)
  app = write_app(dir, "slowboot.ru", SLOW_BOOT)
  w = WorkerProc.new(dir, app)
  w.await_entered
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  w.term
  st = w.wait_exit(5)
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
  check("SIGTERM during startup terminates the worker promptly",
        !st.nil? && st.termsig == 15 && elapsed < 2.0,
        "st=#{st.inspect} elapsed=#{elapsed.round(3)}s")
  w.reap!
end

with_worker(SLOW3000, { "OXO_WORKER_DRAIN_DEADLINE_MS" => "200" }) do |w|
  w.await_ready
  conn = w.connect
  conn.write(encode_request)
  w.await_entered
  w.term
  status = read_status(conn)
  check("abandoned in-flight request receives a 500 error frame", status == 500,
        status.inspect)
  st = w.wait_exit
  check("worker exits successfully after the cooperative application finishes", st&.exitstatus == 0, st.inspect)
  expiry = w.stderr_text[/\{"oxo_async_worker":"drain_deadline_expired","abandoned_in_flight":(\d+)\}/, 1]
  check("deadline-expiry diagnostic counts one abandoned connection", expiry == "1",
        w.stderr_text.lines.last(3).join)
end

Dir.mktmpdir("oxo-lifecycle-perm") do |dir|
  File.chmod(0o755, dir)
  app = write_app(dir, "app.ru", TRIVIAL)
  w = WorkerProc.new(dir, app)
  st = w.wait_exit(15)
  check("startup rejects a socket directory accessible by other users",
        !st.nil? && st.exitstatus == 1 && w.stderr_text.include?("group/other-accessible"),
        "st=#{st.inspect} stderr=#{w.stderr_text.lines.last(2).join}")
  w.reap!
end

if $checks != 14
  $failures += 1
  puts "FAIL: only #{$checks}/14 checks executed"
end
puts $failures.zero? ? "ASYNC LIFECYCLE: ALL PASS (#{$checks} checks)" : "ASYNC LIFECYCLE: #{$failures}/#{$checks} FAILED"
exit($failures.zero? ? 0 : 1)
