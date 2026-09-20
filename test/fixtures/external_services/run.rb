# frozen_string_literal: true
# Only this launcher supplies destructive test operations with service identities.
require_relative "../../conformance/support"
require "securerandom"
require "open3"
require "json"
require "timeout"

begin
  abort "requires Linux and an existing local Docker Compose installation" unless RUBY_PLATFORM.include?("linux")
  build_env = { "PATH" => ENV.fetch("PATH"),
                "CARGO_HOME" => ENV.fetch("CARGO_HOME", File.join(ENV.fetch("HOME"), ".cargo")),
                "RUSTUP_HOME" => ENV.fetch("RUSTUP_HOME", File.join(ENV.fetch("HOME"), ".rustup")) }
  %w[CARGO_TARGET_DIR OXO_TEST_WORKER_BIN].each { |key| build_env[key] = ENV[key] if ENV[key] }
  ENV.replace(Conformance.child_env.merge(build_env))
  id = "oxo-external-#{SecureRandom.hex(12)}"
  Dir.mktmpdir("#{id}-") do |dir|
    project = File.basename(dir).downcase.gsub(/[^a-z0-9-]/, "")
    password = SecureRandom.hex(32)
    env_file = File.join(dir, "compose.env")
    File.write(env_file, "TEST_PASSWORD=#{password}\n", perm: 0o600)
    compose = ["docker", "compose", "--project-name", project,
               "--env-file", env_file, "--file", File.join(__dir__, "compose.yaml")]
    run = lambda do |argv, strict = true|
      status = nil
      out = err = ""
      Dir.mktmpdir("command-", dir) do |command_dir|
        stdout = File.join(command_dir, "stdout")
        stderr = File.join(command_dir, "stderr")
        pid = Process.spawn(*argv, pgroup: true, in: File::NULL, out: stdout, err: stderr)
        begin
          Timeout.timeout(120) { status = Process.wait2(pid).last }
        ensure
          unless status
            Process.kill("KILL", -pid) rescue Errno::ESRCH
            Process.wait(pid) rescue Errno::ECHILD
          end
        end
        out = File.binread(stdout, 65_536)
        err = File.binread(stderr, 65_536)
      end
      unless status.success?
        warn Conformance.diagnostic(err).gsub(password, "<test-secret>")
        raise "owned service command failed" if strict
      end
      out
    end
    # Disallow inherited remote contexts, credentials or arbitrary Docker sockets.
    endpoint = JSON.parse(run.call(["docker", "context", "inspect", "default"]))
      .fetch(0).fetch("Endpoints").fetch("docker").fetch("Host")
    abort "requires the default local Docker socket" unless endpoint == "unix:///var/run/docker.sock"
    run.call(["docker", "compose", "version"])
    begin
      run.call(compose + ["up", "--detach", "--wait", "--wait-timeout", "60"])
      port = lambda do |service, internal|
        value = run.call(compose + ["port", service, internal.to_s]).strip
        match = /\A127\.0\.0\.1:(\d+)\z/.match(value) or raise "non-loopback service binding"
        Integer(match[1])
      end
      pg_port, redis_port = port.call("postgres", 5432), port.call("redis", 6379)
      File.write(File.join(dir, "owned.env"), "PROJECT=#{project}\nPG_PORT=#{pg_port}\nREDIS_PORT=#{redis_port}\nPASSWORD=#{password}\n", perm: 0o600)
      # The runner supplies a fresh identity and URLs; no developer service URL is accepted.
      system({"OXO_TEST_EXTERNAL_DIR" => dir}, RbConfig.ruby, File.join(Conformance::ROOT, "test/run.rb"), "external-child")
      result = $CHILD_STATUS || $?
    ensure
      begin
        run.call(compose + ["unpause"], false)
      ensure
        # Even a hung unpause must not prevent the project's removal attempt.
        run.call(compose + ["down", "--volumes", "--remove-orphans", "--timeout", "5"])
        remaining = run.call(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=#{project}"])
        raise "owned containers survived cleanup" unless remaining.strip.empty?
      end
    end
    exit(result&.success? ? 0 : 1)
  end

rescue StandardError => error
  warn Conformance.diagnostic("#{error.class}: #{error.message}")
  exit 1
end
