# frozen_string_literal: true
# Process fixture shared by lifecycle and worker configuration tests.
class WorkerProc
  attr_reader :pid, :socket, :stdout_r, :stderr_path

  def initialize(dir, app_path, extra_env = {})
    @socket = File.join(dir, "worker.sock")
    @entered = File.join(dir, "entered")
    @release = File.join(dir, "release")
    @reaped = false
    @stderr_path = File.join(dir, "stderr.log")
    @stdout_r, stdout_w = IO.pipe
    @pid = Process.spawn(
      Conformance.child_env.merge("OXO_TEST_ENTERED" => @entered, "OXO_TEST_RELEASE" => @release).merge(extra_env),
      RbConfig.ruby, WORKER, @socket, app_path,
      out: stdout_w, err: @stderr_path, in: File::NULL, unsetenv_others: true, pgroup: true
    )
    stdout_w.close
  end

  def await_ready(timeout_s = 30)
    line = Timeout.timeout(timeout_s) { @stdout_r.gets }
    [line, nil]
  rescue Timeout::Error
    [nil, nil]
  end

  def connect
    UNIXSocket.new(@socket)
  end

  def await_entered
    Timeout.timeout(10) { sleep 0.01 until File.exist?(@entered) }
  end

  def release
    File.write(@release, "release")
  end

  def term
    Process.kill("TERM", @pid)
  end

  def wait_exit(timeout_s = 5)
    status = Timeout.timeout(timeout_s) { Process.wait2(@pid).last }
    @reaped = true
    status
  rescue Timeout::Error
    nil
  end

  def reap!
    @stdout_r.close unless @stdout_r.closed?
    return if @reaped
    Process.kill("KILL", -@pid)
    Process.wait2(@pid)
    @reaped = true
  rescue Errno::ESRCH, Errno::ECHILD
    nil
  end

  def stderr_text
    File.exist?(@stderr_path) ? Conformance.diagnostic(File.read(@stderr_path)) : ""
  end
end
