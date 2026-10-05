# frozen_string_literal: true
require "rbconfig"
require "tmpdir"
require "fileutils"

module Conformance
  ROOT = File.expand_path("../..", __dir__)
  ORIGINAL_HOME = ENV["HOME"]
  HOME = Dir.mktmpdir("oxo-conformance-home")
  at_exit { FileUtils.remove_entry_secure(HOME) if File.directory?(HOME) }

  def self.child_env
    {
      "PATH" => "#{File.dirname(RbConfig.ruby)}:/usr/local/bin:/usr/bin:/bin",
      "HOME" => HOME,
      "LANG" => "C.UTF-8",
      "BUNDLE_IGNORE_CONFIG" => "1",
      "BUNDLE_GEMFILE" => File.join(ROOT, "test/fixtures/rack_async/Gemfile"),
      "BUNDLE_APP_CONFIG" => File.join(HOME, "bundle"),
      "BUNDLE_USER_HOME" => File.join(HOME, "bundle-user"),
      "RUBYOPT" => "-rbundler/setup",
      "LD_LIBRARY_PATH" => RbConfig::CONFIG.fetch("libdir")
    }
  end

  def self.clean_environment!
    ENV.replace(child_env)
  end

  def self.diagnostic(text)
    text = text.byteslice(0, 65_536).to_s.gsub(ROOT, "<workspace>").gsub(HOME, "<test-home>")
    text = text.gsub(ORIGINAL_HOME, "<home>") if ORIGINAL_HOME && !ORIGINAL_HOME.empty?
    text
  end
end
