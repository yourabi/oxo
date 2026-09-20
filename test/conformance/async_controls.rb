# frozen_string_literal: true
require_relative "support"
Conformance.clean_environment!
require "socket"
require "timeout"
require_relative "frame"
WORKER = File.join(Conformance::ROOT, "ruby/oxo_async_worker.rb")
require_relative "worker"

checks = 0
[[{}, 0, 0], [{"OXO_WORKER_SCHED" => "nice:5"}, 5, 0], [{"OXO_WORKER_SCHED" => "idle"}, 0, 5]].each do |env, nice, policy|
  Dir.mktmpdir("oxo-controls") do |dir|
    app = File.join(dir, "app.ru")
    File.write(app, "run ->(env) { [200, {}, ['ok']] }\n")
    w = WorkerProc.new(dir, app, env)
    begin
      line, = w.await_ready
      raise "worker not ready" unless line == "OXO_WORKER_READY=#{w.socket}\n"
      w.connect.tap { |io| io.write(simple_frame('/ok')); raise "request failed" unless read_response(io)[0] == 200 }.close
      fields = File.read("/proc/#{w.pid}/stat").split(') ').last.split
      raise "requested child scheduling policy not realized" unless fields[16].to_i == nice && fields[38].to_i == policy
      w.term
      raise "worker failed to exit" unless w.wait_exit&.success?
      raise "default fair-read setting not selected" unless w.stderr_text.include?("fair_read=yield2")
      checks += 1
    ensure
      w.reap!
    end
  end
end
%w[nice:20 rt fifo].each do |bad|
  Dir.mktmpdir("oxo-controls-invalid") do |dir|
    app = File.join(dir, "app.ru")
    File.write(app, "raise 'application must not boot'\n")
    w = WorkerProc.new(dir, app, {"OXO_WORKER_SCHED" => bad})
    begin
      line, = w.await_ready
      status = w.wait_exit
      raise "invalid setting was not rejected at boot" unless line.nil? && status&.exitstatus == 1 && w.stderr_text.include?("is not unset, nice:<0..19> or idle")
      checks += 1
    ensure
      w.reap!
    end
  end
end
raise "configuration coverage incomplete" unless checks == 6
puts "ASYNC CONTROLS: 6 checks passed (default, realized child settings, invalid settings)"
