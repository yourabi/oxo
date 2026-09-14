# The trivial Rack app serves through both handlers. It is intentionally minimal
# — proves the seam end-to-end, not a real framework (real Rails is the
# milestone). Loaded via Rack::Builder.parse_file, so it uses the `run` DSL.

app = lambda do |env|
  body = +""
  body << "Hello from Oxo!\n"
  body << "REQUEST_METHOD=#{env['REQUEST_METHOD']}\n"
  body << "PATH_INFO=#{env['PATH_INFO']}\n"
  body << "QUERY_STRING=#{env['QUERY_STRING']}\n"

  # /raise lets tests verify the error path (Ruby raises -> edge returns 500 and the
  # worker/Ruby-thread survives for the next request).
  raise "boom (intentional)" if env["PATH_INFO"] == "/raise"

  # /echo returns the request body, exercising rack.input.
  if env["PATH_INFO"] == "/echo"
    body = env["rack.input"].read
  end

  [200, { "content-type" => "text/plain; charset=utf-8" }, [body]]
end

run app
