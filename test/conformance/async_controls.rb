# frozen_string_literal: true
require_relative "support"
Conformance.clean_environment!
require "socket"
require "timeout"
require_relative "frame"
WORKER = File.join(Conformance::ROOT, "ruby/oxo_async_worker.rb")
require_relative "worker"

DARWIN = RUBY_PLATFORM.include?("darwin")

# [nice, policy] the kernel reports for a child. Linux reads procfs; macOS has no
# procfs and no SCHED_IDLE, so only the nice value is observable there.
def realized_scheduling(pid)
  if DARWIN
    [Integer(IO.popen(["ps", "-o", "nice=", "-p", pid.to_s], &:read).strip), 0]
  else
    fields = File.read("/proc/#{pid}/stat").split(") ").last.split
    [fields[16].to_i, fields[38].to_i]
  end
end

checks = 0
# The default case inherits this process's nice value, which is not zero on every
# host (GitHub's macOS runners, for one); nice:5 is absolute.
inherited_nice = Process.getpriority(Process::PRIO_PROCESS, 0)
cases = [[{}, inherited_nice, 0], [{"OXO_WORKER_SCHED" => "nice:5"}, 5, 0]]
# SCHED_IDLE is applied with util-linux chrt: Linux only.
cases << [{"OXO_WORKER_SCHED" => "idle"}, 0, 5] unless DARWIN
cases.each do |env, nice, policy|
  Dir.mktmpdir("oxo-controls") do |dir|
    app = File.join(dir, "app.ru")
    File.write(app, "run ->(env) { [200, {}, ['ok']] }\n")
    w = WorkerProc.new(dir, app, env)
    begin
      line, = w.await_ready
      raise "worker not ready" unless line == "OXO_WORKER_READY=#{w.socket}\n"
      w.connect.tap { |io| io.write(simple_frame('/ok')); raise "request failed" unless read_response(io)[0] == 200 }.close
      realized = realized_scheduling(w.pid)
      raise "requested child scheduling policy not realized: want #{[nice, policy].inspect}, got #{realized.inspect}" unless realized == [nice, policy]
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
if DARWIN
  # Without chrt the idle policy must refuse to boot, never silently run as normal priority.
  Dir.mktmpdir("oxo-controls-idle") do |dir|
    app = File.join(dir, "app.ru")
    File.write(app, "raise 'application must not boot'\n")
    w = WorkerProc.new(dir, app, {"OXO_WORKER_SCHED" => "idle"})
    begin
      line, = w.await_ready
      status = w.wait_exit
      raise "idle policy was not refused on macOS" unless line.nil? && status&.exitstatus == 1 && w.stderr_text.include?("chrt")
      checks += 1
    ensure
      w.reap!
    end
  end
end
raise "configuration coverage incomplete" unless checks == 6
puts "ASYNC CONTROLS: 6 checks passed (default, realized child settings, invalid settings)"
