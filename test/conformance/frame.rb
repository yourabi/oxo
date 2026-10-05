# frozen_string_literal: true
# Independent protocol bytes; intentionally does not load the worker implementation.
FRAME_MAGIC = 0xBF
FRAME_VERSION = 0x01
PREFIX_LEN = 6

def enc_short(s) = [s.bytesize].pack("v") + s.b
def enc_long(s) = [s.bytesize].pack("V") + s.b

def encode_request(method:, path:, query:, server_name:, server_port:, scheme_byte:, remote_addr:, headers:, body:)
  env = +"".b
  env << enc_short(method)
  env << enc_long(path)
  env << enc_long(query)
  env << enc_short(server_name)
  env << [server_port].pack("v")
  env << [scheme_byte].pack("C")
  env << enc_short(remote_addr)
  env << [headers.length].pack("v")
  headers.each { |k, v| env << enc_short(k) << enc_long(v) }
  env << [body.bytesize].pack("V") << body.b
  [FRAME_MAGIC, FRAME_VERSION].pack("C2") + [env.bytesize].pack("V") + env
end

def golden_frame
  body = "golden-body-bytes"
  encode_request(
    method: "POST",
    path: "/echo",
    query: "a=1&b=two",
    server_name: "parity.test",
    server_port: 8443,
    scheme_byte: 1, # https
    remote_addr: "203.0.113.9",
    headers: [
      ["host", "parity.test"],
      ["user-agent", "oxo-conformance/1.0"],
      ["x-custom-thing", "custom-value"],
      ["cookie", "s=abc; t=def"],
      ["content-type", "application/octet-stream"],
      ["content-length", body.bytesize.to_s],
      ["x-forwarded-for", "192.0.2.6"],        # forwarding denylist -> dropped
      ["client-ip", "192.0.2.7"],              # forwarding denylist -> dropped
      ["x-oxo-evil", "spoof"],           # reserved namespace -> dropped
      ["connection", "keep-alive"],          # hop-by-hop -> dropped
      ["bad_name", "underscore"],            # '_' name -> dropped (normalize)
      ["X-MiXeD-CaSe", "lowered"]            # defensive re-lower -> HTTP_X_MIXED_CASE
    ],
    body: body
  )
end

def simple_frame(path, query = "")
  encode_request(
    method: "GET", path: path, query: query, server_name: "localhost",
    server_port: 80, scheme_byte: 0, remote_addr: "127.0.0.1",
    headers: [["host", "localhost"]], body: ""
  )
end

def read_exact(io, n)
  buf = +"".b
  while buf.bytesize < n
    chunk = io.read(n - buf.bytesize)
    raise "EOF after #{buf.bytesize}/#{n} bytes" if chunk.nil? || chunk.empty?
    buf << chunk
  end
  buf
end

def read_response(io)
  prefix = read_exact(io, PREFIX_LEN)
  raise "bad magic" unless prefix.getbyte(0) == FRAME_MAGIC && prefix.getbyte(1) == FRAME_VERSION
  env = read_exact(io, prefix.byteslice(2, 4).unpack1("V"))
  pos = 0
  kind = env.getbyte(pos); pos += 1
  raise "not a Full frame (kind=#{kind})" unless kind.zero?
  status = env.byteslice(pos, 2).unpack1("v"); pos += 2
  hcount = env.byteslice(pos, 2).unpack1("v"); pos += 2
  headers = Array.new(hcount) do
    nlen = env.byteslice(pos, 2).unpack1("v"); pos += 2
    name = env.byteslice(pos, nlen); pos += nlen
    vlen = env.byteslice(pos, 4).unpack1("V"); pos += 4
    value = env.byteslice(pos, vlen); pos += vlen
    [name, value]
  end
  blen = env.byteslice(pos, 4).unpack1("V"); pos += 4
  [status, headers, env.byteslice(pos, blen)]
end
