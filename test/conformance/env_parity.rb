# frozen_string_literal: true
require_relative "support"
require_relative "frame"
require "socket"
require "open3"
require "stringio"
require "json"
require "timeout"

worker = ENV.fetch("OXO_TEST_WORKER_BIN")
abort "prebuilt absolute worker binary required" unless worker.start_with?("/") && File.executable?(worker)
Conformance.clean_environment!
app = File.join(Conformance::ROOT, "test/async_worker/echo_env.ru")
async = File.join(Conformance::ROOT, "ruby/oxo_async_worker.rb")
frame = golden_frame
Dir.mktmpdir("oxo-env-parity") do |dir|
  socket = File.join(dir, "worker.sock")
  env = Conformance.child_env.merge("OXO_WORKER_APP" => app, "OXO_WORKER_SOCKET" => socket,
    "OXO_WORKER_THREADS" => "1", "OXO_WORKER_MULTIPROCESS" => "0")
  log = File.join(dir, "worker.log")
  pid = Process.spawn(env, worker, unsetenv_others: true, pgroup: true, out: log, err: log)
  begin
    Timeout.timeout(30) { sleep 0.01 until File.socket?(socket) && File.stat(socket).mode & 0o777 == 0o600 }
    classic = Timeout.timeout(10) do
      UNIXSocket.open(socket) { |io| io.write(frame); read_response(io) }
    end
    raise "native worker did not answer 200" unless classic[0] == 200
    # Exact same frame, body bytes, application and rack.* settings.
    out, err, status = Open3.capture3(Conformance.child_env, RbConfig.ruby, async, "--filter", app, stdin_data: frame, binmode: true, unsetenv_others: true)
    raise Conformance.diagnostic(err) unless status.success?
    ruby_result = read_response(StringIO.new(out))
    raise "Rack environment bytes differ" unless ruby_result[0] == 200 && classic[2] == ruby_result[2]
    value = JSON.parse(ruby_result[2])
    raise "native/async topology flags differ" unless value['rack.multiprocess'] == false && value['rack.multithread'] == false
    out, err, status = Open3.capture3(Conformance.child_env.merge("OXO_WORKER_MULTIPROCESS" => "1"), RbConfig.ruby, async, "--filter", app, stdin_data: frame, binmode: true, unsetenv_others: true)
    raise Conformance.diagnostic(err) unless status.success?
    multi = read_response(StringIO.new(out))
    raise "multiprocess flag did not change" unless multi[0] == 200 && JSON.parse(multi[2])['rack.multiprocess'] == true
    puts "ENV PARITY: 3 checks passed (identical frame and Rack env; both topology flag polarities)"
  ensure
    Process.kill("KILL", -pid) rescue Errno::ESRCH
    Process.wait(pid) rescue Errno::ECHILD
  end
end
