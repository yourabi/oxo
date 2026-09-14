# encoding: utf-8
# B1 env-parity echo app: returns the Rack env as sorted JSON. Loaded by BOTH the S1
# oxo-worker binary and the async worker for the SAME golden frame; the two JSON
# bodies must be byte-identical (the env-parity contract). NOTE: the S1 embedded VM
# parses source as US-ASCII unless told otherwise, so this file stays ASCII-only with
# the encoding comment above as a belt-and-braces guard.
#
# Non-serializable env values are normalized identically on both sides:
# rack.input -> its full read content as hex (proves body plumbing, not identity)
# rack.errors -> the marker "<errors>"
# Everything else is emitted verbatim (String/bool). Keys are sorted for a stable diff.
require "json"

run lambda { |env|
  out = {}
  env.each do |k, v|
    out[k] =
      case k
      when "rack.input" then v.read.force_encoding(Encoding::BINARY).unpack1("H*")
      when "rack.errors" then "<errors>"
      else
        v.is_a?(String) || v == true || v == false ? v : "<#{v.class}>"
      end
  end
  body = JSON.generate(out.sort.to_h)
  [200, { "content-type" => "application/json" }, [body]]
}
