require_relative "boot"
require "rails"
require "active_model/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "action_cable/engine"
require "active_record/railtie" if ENV["RAILS_ENV"] == "production_external"
require "logger"

groups = Rails.groups
groups << :external_services if ENV["RAILS_ENV"] == "production_external"
Bundler.require(*groups)

module OxoFixture
  class Application < Rails::Application
    config.load_defaults 8.1
    config.api_only = true
    config.active_support.isolation_level = :fiber if ENV["OXO_ASYNC"] == "1"
    config.autoload_lib(ignore: %w[assets tasks])
    config.secret_key_base = ENV.fetch("SECRET_KEY_BASE")
    config.session_store :cookie_store, key: "_oxo_session"
    config.middleware.use ActionDispatch::Cookies
    config.middleware.use config.session_store, config.session_options
    config.action_cable.mount_path = "/cable"
    config.action_cable.allowed_request_origins = ["http://app.example", "https://app.example"]
    # Assertions inspect protocol results, not a log of the local environment.
    config.logger = Logger.new(File::NULL)
    config.log_level = :fatal
  end
end
