# frozen_string_literal: true
require "timeout"
require "rbconfig"

# One Linux session per command: descendants may create process groups, as the
# service does, but remain owned by the command's session. Cleanup checks the
# session id from /proc, never a process-name match or an ambient service id.
module TestCommand
  def self.members(session)
    Dir.glob("/proc/[0-9]*/stat").filter_map do |path|
      stat = File.read(path)
      fields = stat[(stat.rindex(") ") + 2)..].split
      next unless fields[3].to_i == session && fields[0] != "Z"
      Integer(File.basename(File.dirname(path)))
    rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
      nil
    end
  end

  def self.run(env, argv, directory:, log:, timeout:)
    bootstrap = "Process.setsid; exec([ARGV[0], ARGV[0]], *ARGV.drop(1))"
    pid = Process.spawn(env, RbConfig.ruby, "-e", bootstrap, *argv,
      chdir: directory, unsetenv_others: true,
      in: File::NULL, out: log, err: [:child, :out])
    status = nil
    expired = false
    leaked = []
    begin
      Timeout.timeout(timeout) { status = Process.wait2(pid).last }
    rescue Timeout::Error
      expired = true
    ensure
      # Observe surviving processes before forced cleanup. A successful exit
      # that leaves a worker running must not be reported as successful teardown.
      leaked = members(pid)
      leaked.each { |member| Process.kill("KILL", member) rescue Errno::ESRCH }
      unless status
        Process.kill("KILL", pid) rescue Errno::ESRCH
        Process.wait(pid) rescue Errno::ECHILD
      end
    end
    [status, expired, !leaked.empty?]
  end
end
