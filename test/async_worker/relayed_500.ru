# Increment a file-backed invocation count before /raise throws. A replay would
# increment twice. Other paths return 200 so tests can warm the connection pool.
COUNT_FILE = ENV.fetch("OXO_TEST_COUNT_FILE")

run lambda { |env|
  if env["PATH_INFO"] == "/raise"
    n = (File.exist?(COUNT_FILE) ? File.read(COUNT_FILE).to_i : 0) + 1
    File.write(COUNT_FILE, n.to_s)
    raise "intentional app failure (relayed-500 oracle)"
  end
  [200, { "content-type" => "text/plain" }, ["warm-ok"]]
}
