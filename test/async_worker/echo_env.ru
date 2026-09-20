# encoding: utf-8
# Return the Rack environment as sorted JSON. Native and async workers receive
# the same frame and must produce identical bodies. Keep source ASCII-compatible
# and declare UTF-8 for the embedded Ruby parser.
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
