# frozen_string_literal: true
#
# Oxo-owned Puma config, passed via `puma -C`. Because `-C` is given, Puma does NOT
# auto-load the app's config/puma.rb, so the worker's bind + mode are Oxo's decision
# — the app cannot widen the bind to a public interface, and there is no cluster to
# orphan on shutdown.

# Bind loopback-only, on the exact port the edge picked (the worker-socket fence).
chosen_port = Integer(ENV.fetch("OXO_PUMA_PORT"))
bind "tcp://127.0.0.1:#{chosen_port}"

workers 0          # single mode: exactly one process — nothing to orphan
threads 1, 5       # in-worker thread pool (Puma releases the GVL on I/O)
quiet              # no per-connection logging on stdout after boot
environment ENV.fetch("RAILS_ENV", "development")

# Emit the readiness sentinel AFTER the app has fully booted (not Puma's early
# "Listening" banner). The edge reads `OXO_PORT=` from stdout as both the port
# handshake and a true readiness signal, then stops reading the pipe.
on_booted do
  $stdout.sync = true
  $stdout.puts("OXO_PORT=#{chosen_port}")
  $stdout.flush
end
