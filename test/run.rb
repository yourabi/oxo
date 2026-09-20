# frozen_string_literal: true
# Correctness runner with bounded commands, isolated Ruby fixtures,
# redacted diagnostics and explicit test selection.
require_relative "conformance/support"
require_relative "conformance/command"
require "json"
require "timeout"
require "securerandom"

module TestRunner
  ROOT = Conformance::ROOT
  ORIGINAL = ENV.to_h
  PATH = ORIGINAL.fetch("PATH")
  SECRET = SecureRandom.hex(64)

  def self.environment
    env = Conformance.child_env.merge("PATH" => PATH,
      "SECRET_KEY_BASE" => SECRET, "OXO_TEST_HOME_ROOT" => Conformance::HOME)
    # Cargo uses the existing toolchain/cache, without changing global settings.
    %w[CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR OXO_TEST_WORKER_BIN OXO_TEST_EXTERNAL_DIR].each do |name|
      env[name] = ORIGINAL[name] if ORIGINAL[name]
    end
    env["CARGO_HOME"] ||= File.join(ORIGINAL.fetch("HOME"), ".cargo")
    env["RUSTUP_HOME"] ||= File.join(ORIGINAL.fetch("HOME"), ".rustup")
    env["RUBY"] = RbConfig.ruby
    env
  end

  def self.redact(text)
    result = Conformance.diagnostic(text).gsub(SECRET, "<test-secret>")
    %w[CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR OXO_TEST_WORKER_BIN OXO_TEST_EXTERNAL_DIR].each do |key|
      value = ORIGINAL[key]
      result = result.gsub(value, "<test-path>") if value && !value.empty?
    end
    if (dir = ORIGINAL["OXO_TEST_EXTERNAL_DIR"]) && File.file?(File.join(dir, "owned.env"))
      password = File.readlines(File.join(dir, "owned.env")).find { |line| line.start_with?("PASSWORD=") }&.split("=", 2)&.last&.strip
      result = result.gsub(password, "<test-secret>") if password && !password.empty?
    end
    result
  end

  def self.run(label, argv, timeout: 900)
    puts "RUN #{label}"
    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    status = nil
    expired = false
    leaked = false
    Dir.mktmpdir("oxo-command") do |dir|
      log = File.join(dir, "output")
      child_env = environment
      if argv.first == 'cargo'
        child_env.delete('BUNDLE_GEMFILE')
        child_env.delete('RUBYOPT')
      end
      status, expired, leaked = TestCommand.run(child_env, argv, directory: ROOT, log: log, timeout: timeout)
      # Drain to a private file while running, then render only a bounded tail.
      # A verbose child can never block on a pipe held by this runner.
      counts = { passed: 0, failed: 0, ignored: 0, measured: 0, filtered_out: 0 }
      File.foreach(log) do |line|
        if (match = /test result: .*? (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out/.match(line))
          counts.keys.zip(match.captures).each { |key, value| counts[key] += Integer(value) }
        end
      end
      puts "CARGO COUNTS #{JSON.generate(counts)}" if argv.first == 'cargo' && argv.include?('test')
      File.open(log, "rb") do |file|
        file.seek([file.size - 65_536, 0].max)
        puts redact(file.read)
      end
    end
    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
    raise "#{label} timed out after #{timeout}s" if expired
    raise "#{label} left owned processes running (cleaned up)" if leaked
    raise "#{label} failed (#{status&.exitstatus})" unless status&.success?
    puts "PASS #{label} (#{elapsed.round(2)}s)"
  end

  def self.main(mode)
    abort "Linux integration runner; Windows keeps the cross-platform cargo suite" unless RUBY_PLATFORM.include?("linux")
    target = ORIGINAL["CARGO_TARGET_DIR"] || File.join(ROOT, "target")
    ORIGINAL["OXO_TEST_WORKER_BIN"] ||= File.expand_path("debug/oxo-worker", target)
    case mode
    when "workspace"
      run("build worker", %w[cargo build --locked -p oxo-worker])
      run("workspace", %w[cargo test --locked --workspace])
      run("real Puma/Rails", %w[cargo test --locked -p oxo-edge --test puma_rails -- --ignored])
      run("native worker/Rails", %w[cargo test --locked -p oxo-worker --test worker_uds rails_fixture_serves_request -- --ignored --exact])
    when "tls"
      run("build worker", %w[cargo build --locked -p oxo-worker])
      run("TLS and gRPC", %w[cargo test --locked -p oxo-pingora-edge --features tls-rustls --test grpc_public --test worker_e2e -- --test-threads=1])
    when "conformance"
      run("build worker", %w[cargo build --locked -p oxo-worker])
      %w[privacy async_protocol async_lifecycle async_controls env_parity].each do |name|
        run(name, [RbConfig.ruby, "test/conformance/#{name}.rb"], timeout: 120)
      end
    when "external-child"
      raise "owned external launcher required" unless ORIGINAL["OXO_TEST_EXTERNAL_DIR"]
      run("build worker", %w[cargo build --locked -p oxo-worker])
      run("real PostgreSQL and Redis", %w[cargo test --locked -p oxo-pingora-edge --test external_pressure -- --ignored --test-threads=1])
    else
      abort "usage: ruby test/run.rb workspace|tls|conformance\nExternal tier: ruby test/fixtures/external_services/run.rb"
    end
  end
end

if $PROGRAM_NAME == __FILE__
  begin
    TestRunner.main(ARGV.fetch(0, "workspace"))
  rescue StandardError => error
    warn TestRunner.redact("#{error.class}: #{error.message}")
    exit 1
  end
end
