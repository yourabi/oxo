allowed_hosts = ENV.fetch("OXO_RAILS_ALLOWED_HOSTS", "").split(",").map(&:strip).reject(&:empty?)
Rails.application.config.hosts.clear
allowed_hosts.each { |host| Rails.application.config.hosts << host }
