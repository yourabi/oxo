# frozen_string_literal: true
require_relative "../run"
require "open3"

# Deliberately hostile ambient configuration must not reach a failing fixture.
sentinel = "synthetic-private-sentinel-#{SecureRandom.hex(16)}"
ENV["AWS_SECRET_ACCESS_KEY"] = sentinel
ENV["DATABASE_URL"] = "postgres://#{sentinel}@private.invalid/never"
ENV["RUBYOPT"] = "-e#{sentinel}"
ENV["BUNDLE_GEMFILE"] = "/#{sentinel}/Gemfile"
env = Conformance.child_env
out, err, status = Open3.capture3(env, RbConfig.ruby, "-e",
  'puts ENV.values.join("|"); warn "synthetic child failure"; exit 7', unsetenv_others: true)
raise "sentinel reached failing child" if (out + err).include?(sentinel)
raise "failure witness did not execute" unless status.exitstatus == 7 && err.include?("synthetic child failure")
redacted = TestRunner.redact("#{Conformance::ROOT} #{Conformance::ORIGINAL_HOME} #{TestRunner::SECRET}")
raise "failure renderer leaked a private value" if redacted.include?(Conformance::ROOT) || redacted.include?(TestRunner::SECRET) || (Conformance::ORIGINAL_HOME && redacted.include?(Conformance::ORIGINAL_HOME))

Dir.mktmpdir("oxo-command-witness") do |dir|
  # The leaked child creates its own process group, matching the service's
  # topology. A root-only group kill would miss it.
  status, expired, leaked = TestCommand.run(Conformance.child_env,
    [RbConfig.ruby, "-e", "Process.spawn(RbConfig.ruby, '-e', 'sleep 60', pgroup: true)"],
    directory: dir, log: File.join(dir, "leak.log"), timeout: 5)
  raise "leaked process was counted as clean teardown" unless status&.success? && !expired && leaked
  status, expired, leaked = TestCommand.run(Conformance.child_env,
    [RbConfig.ruby, "-e", "sleep 60"],
    directory: dir, log: File.join(dir, "timeout.log"), timeout: 0.2)
  # A short deadline can expire during Ruby startup, before setsid executes.
  # It must still be reported and the root reaped; a session leak is not required.
  raise "command timeout was hidden" unless status.nil? && expired
end
puts "PRIVACY/LIFECYCLE: 5 checks passed (failing-child isolation, redaction, leak detection and timeout cleanup)"
