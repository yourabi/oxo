Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = true
  config.consider_all_requests_local = false
  config.assume_ssl = true
  config.force_ssl = true
  config.silence_healthcheck_path = "/up"
  config.active_support.report_deprecations = false
end
