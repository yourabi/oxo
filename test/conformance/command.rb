# frozen_string_literal: true
require "timeout"
require "rbconfig"

# One session per command: descendants may create process groups, as the
# service does, but remain owned by the command's session. Cleanup checks the
# session id (procfs on Linux, getsid on macOS), never a process-name match or
# an ambient service id.
module TestCommand
  def self.members(session)
    return darwin_members(session) if RUBY_PLATFORM.include?("darwin")

    Dir.glob("/proc/[0-9]*/stat").filter_map do |path|
      stat = File.read(path)
      fields = stat[(stat.rindex(") ") + 2)..].split
      next unless fields[3].to_i == session && fields[0] != "Z"
      Integer(File.basename(File.dirname(path)))
    rescue Errno::ENOENT, Errno::ESRCH, Errno::EACCES
      nil
    end
  end

  # macOS has no procfs and its pgrep cannot filter by session: list every
  # process once and ask the kernel for each one's session id. Zombies are
  # skipped the same way the Linux scan skips state "Z".
  def self.darwin_members(session)
    IO.popen(["ps", "-axo", "pid=,stat="], &:read).each_line.filter_map do |line|
      pid, state = line.split
      next if pid.nil? || state.nil? || state.start_with?("Z")
      pid = Integer(pid)
      pid if Process.getsid(pid) == session
    rescue Errno::ESRCH, Errno::EPERM, ArgumentError
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
      unless leaked.empty?
        listing = `ps -o pid=,command= -p #{leaked.join(",")}`.strip
        warn "owned processes still running after the command exited:\n#{listing}"
      end
      leaked.each { |member| Process.kill("KILL", member) rescue Errno::ESRCH }
      unless status
        Process.kill("KILL", pid) rescue Errno::ESRCH
        Process.wait(pid) rescue Errno::ECHILD
      end
    end
    [status, expired, !leaked.empty?]
  end
end
