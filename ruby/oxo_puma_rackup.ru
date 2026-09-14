# frozen_string_literal: true
#
# Oxo-owned rackup wrapper. Puma runs THIS; it loads the user's real app (Rails or
# any Rack app) and wraps it in the secret gate — no edits to the user's config.ru. The
# gate is the OUTERMOST middleware, so it runs before any of the app's own middleware.

require "rack"

# Constant-time, fail-closed secret gate. Only Oxo's edge knows the secret, so a
# local process that reaches the worker port directly cannot drive the app.
class OxoSecretGate
  def initialize(app, secret)
    @app = app
    @secret = secret.to_s
  end

  def call(env)
    provided = env["HTTP_X_OXO_SECRET"]
    return forbidden if provided.nil? || provided.empty? || !secure_compare(provided, @secret)

    env.delete("HTTP_X_OXO_SECRET") # don't leak the secret to the app
    @app.call(env)
  end

  private

  def forbidden
    [403,
     { "content-type" => "text/plain; charset=utf-8", "x-oxo-gate" => "denied" },
     ["Forbidden (oxo secret gate)"]]
  end

  def secure_compare(a, b)
    return Rack::Utils.secure_compare(a, b) if Rack::Utils.respond_to?(:secure_compare)
    return false unless a.bytesize == b.bytesize

    res = 0
    a.each_byte.zip(b.each_byte) { |x, y| res |= (x ^ y) }
    res.zero?
  end
end

# Load the real app (Rack 3 returns the app; Rack 2 returned [app, options]).
loaded = Rack::Builder.parse_file(ENV.fetch("OXO_WORKER_APP"))
app = loaded.is_a?(Array) ? loaded.first : loaded

use OxoSecretGate, ENV.fetch("OXO_WORKER_SECRET")
run app
