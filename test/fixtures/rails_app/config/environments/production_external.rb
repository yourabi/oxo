require_relative "production"
Rails.application.configure do
  config.action_cable.url = ENV.fetch("OXO_ACTION_CABLE_URL", "ws://app.example/cable")
end
