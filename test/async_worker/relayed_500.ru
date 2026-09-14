# B1 edge-integration app (the corrected contract-2 oracle): /raise raises AFTER
# bumping a file-based invocation counter (the primary no-replay observable — a worker-
# or edge-side replay would show 2). Every other path answers 200 so the pool can warm.
COUNT_FILE = ENV.fetch("OXO_TEST_COUNT_FILE")

run lambda { |env|
  if env["PATH_INFO"] == "/raise"
    n = (File.exist?(COUNT_FILE) ? File.read(COUNT_FILE).to_i : 0) + 1
    File.write(COUNT_FILE, n.to_s)
    raise "intentional app failure (relayed-500 oracle)"
  end
  [200, { "content-type" => "text/plain" }, ["warm-ok"]]
}
