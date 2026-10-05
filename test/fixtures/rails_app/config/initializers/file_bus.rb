# Synthetic fanout/outage coverage; real Redis has its own integration tier.
if ENV["OXO_CABLE_ADAPTER"] == "oxo_file_bus"
  require "action_cable/subscription_adapter/oxo_file_bus"
end
