# frozen_string_literal: true
#
# B1 (graduation arc): the CONNECTION-PER-REQUEST async Ruby worker — `1cr`.
#
# A fiber-per-connection worker on the Ruby `async` reactor, speaking the plain
# `hop_frame` (0xBF) protocol over a 0600 UDS socket, hosting a real Rack/Rails app.
# The edge's pooled frame hop (`WorkerFramePool`) supplies N warm connections for N
# concurrent requests: one request in flight per connection, one FIBER per accepted
# connection. A slow IO wait (DB, sleep) yields its fiber to the reactor, so other
# connections' requests run — async concurrency with request independence via OS
# sockets (the graduation design's transport verdict; no request interleaving exists
# on a connection, so a large response cannot block an unrelated small one).
#
# THE THREE PINNED WORKER CONTRACTS (design §1, the B1 plan's conformance matrix):
#   1. DISPATCH-AFTER-FULL-FRAME-DECODE — the app is invoked only after the complete
#      request frame is read AND decoded. A truncated/malformed frame (decode-error
#      class) closes the connection with NO app call and NO bytes written: the LEGAL
#      pre-dispatch zero-byte-EOF class the edge's stale-retry carve-out relies on.
#   2. ERROR-FRAME-ON-EVERY-POST-DISPATCH-EXIT — once the app is invoked, every exit
#      path either writes the app's response frame or writes a 500 error frame, GUARDED
#      by wrote_response: if any response bytes already reached the socket, the worker
#      closes bare (logged) — a partial frame + appended error frame would corrupt the
#      stream. PINNED OUTCOME: the connection CLOSES after an error frame (conservative;
#      the edge received a complete 500 at a frame boundary, and the closed conn simply
#      fails the pool's liveness probe later — never the retry-eligible zero-byte class).
#   3. WORKER-NEVER-CLOSES-IDLE — the keepalive loop blocks on read with NO timeout.
#      Only the edge retires idle pooled connections (edge-closes-first, invariant);
#      a clean EOF here is the edge's close, answered by closing our side.
#
# ENV CONTRACT (panel HIGH): the Rack env is IDENTICAL to the S1 frame worker's for the
# same RequestFrame — `Oxo.build_env` (crates/oxo-worker/src/linux/ruby.rs:242-294,
# incl. the bounded HTTP_KEY_TABLE) preceded by the S1 frame-path header filter
# (crates/oxo-worker/src/linux/frame.rs:190-228: keep host, drop connection, drop the
# centralized client-forwarding denylist, drop x-oxo-*, reject '_' names). Ported
# verbatim below; this worker's constructed env must match the native S1 worker
# binary's env for the same frame bytes.
# `ruby/oxo_worker.rb` is the legacy -helper and is NOT an env source (its
# build_env hardcodes the scheme and omits REMOTE_ADDR); only its Rack-3 body-collection
# shape is reused.
#
# Wire format (byte-for-byte with the Rust codec, oxo-core/src/hop_frame.rs):
#   * prefix (6B): [magic=0xBF | version=0x01 | remaining_length u32-LE]  (hop_frame.rs:40-43,199)
#   * request envelope: short(method) long(path) long(query) short(server_name) u16(port)
#       u8(scheme: 0=http 1=https) short(remote_addr)
#       headers[u16 count; short(name) long(value)] u32(body)+body        (hop_frame.rs:395-421)
#   * response Full envelope: u8(0=RESP_FULL) u16(status) headers u32(body)+body
#                                                                          (hop_frame.rs:142,468-471)
#   short = u16-LE length prefix; long = u32-LE length prefix.
#
# Boot: sets OXO_ASYNC=1 BEFORE the app loads (the app pins :fiber isolation under
# that flag) and ASSERTS ActiveSupport isolation_level == :fiber after load when
# ActiveSupport is present — a fiber worker over :thread isolation would cross-bleed
# CurrentAttributes/connections between requests sharing a thread.
#
# NOTE: `require "async"`/`require "socket"` are deferred into the server path so the
# offline `--filter` mode (one frame stdin -> one frame stdout, used by the env-parity
# golden and codec checks) runs synchronously under plain `bundle exec ruby`.

require "rack"
require "stringio"
require "json"

FRAME_MAGIC = 0xBF
FRAME_VERSION = 0x01
FRAME_PREFIX_LEN = 6

# Decode caps, mirroring the edge/stub caps (a direct frame client is untrusted; an
# oversized declared length is the decode-error class, never a giant allocation).
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 128
MAX_BODY_BYTES = (ENV["OXO_WORKER_MAX_BODY"] || (4 * 1024 * 1024).to_s).to_i
# hop_frame.rs FRAME_FIXED_SLACK: the prefix pre-check ceiling.
MAX_REMAINING = 4096 + MAX_HEADER_BYTES + MAX_BODY_BYTES

# B2: N sibling reactors run with this set (per-child, spawner-injected — same env name
# the Rust service gives classic workers). Mirrors the S1 worker's env_bool semantics:
# 1/true/yes => true; 0/false/no/absent => false; anything else aborts loudly rather
# than silently defaulting (a typo'd value must not misreport rack.multiprocess).
MULTIPROCESS =
  case (ENV["OXO_WORKER_MULTIPROCESS"] || "0").downcase
  when "1", "true", "yes" then true
  when "0", "false", "no" then false
  else
    abort("oxo-async-worker: invalid OXO_WORKER_MULTIPROCESS=" \
          "#{ENV['OXO_WORKER_MULTIPROCESS'].inspect} (want 1/true/yes or 0/false/no)")
  end

module OxoAsync
  module_function

  # ---- S1 env parity: ported verbatim from Oxo.build_env (ruby.rs:242-294) ----

  # Bounded, pre-seeded frozen key table for the per-header CGI key build (). Names
  # outside the table fall back to the allocating path — NEVER grow the table at runtime
  # (header names are attacker-influenced; a growing memo is a memory-DoS).
  HTTP_KEY_TABLE = %w[
    accept accept-encoding accept-language accept-charset authorization
    cache-control cookie host if-modified-since if-none-match if-match
    if-unmodified-since origin pragma range referer user-agent via date
    upgrade-insecure-requests x-request-id x-requested-with
    sec-fetch-dest sec-fetch-mode sec-fetch-site sec-fetch-user
  ].to_h { |k| [k.freeze, ("HTTP_" + k.upcase.tr("-", "_")).freeze] }.freeze

  # The centralized client-forwarding/real-IP denylist — MUST match
  # oxo_core::is_client_forwarding_header (oxo-core/src/lib.rs:571-591) exactly.
  # Identity (REMOTE_ADDR, scheme, host) comes ONLY from trusted native frame fields.
  FORWARDING_DENYLIST = %w[
    forwarded x-real-ip client-ip true-client-ip cf-connecting-ip cf-pseudo-ipv4
    x-client-ip fastly-client-ip fly-client-ip x-cluster-client-ip
    x-original-forwarded-for x-original-for x-appengine-user-ip x-azure-clientip
    x-azure-socketip x-proxyuser-ip x-forwarded
  ].to_h { |k| [k, true] }.freeze

  def forwarding_header?(name)
    FORWARDING_DENYLIST[name] || name.start_with?("x-forwarded-")
  end

  # The S1 frame-path header filter (frame.rs:190-228): applied to decoded frame headers
  # BEFORE build_env. Re-lowers defensively, keeps host, drops connection, drops the
  # forwarding denylist, drops the reserved x-oxo-* namespace, rejects '_' names
  # (normalize_header_name, lib.rs:541-546 — an underscore name would alias a legitimate
  # dashed header's CGI key).
  #
  # B4: filter + flatten FUSED into one walk emitting the flat [k, v, k, v, ...]
  # list build_env consumes directly. Pre-this was two walks (filter_frame_headers
  # building pair arrays, then flatten_headers_for_env re-walking them) — one array per
  # kept header plus a whole extra pass, per request, per fiber. Same keep/drop rules,
  # same output order; only the intermediate materialization is gone.
  def filtered_flat_headers(headers)
    flat = []
    headers.each do |name, value|
      lower = name.downcase
      if lower == "host"
        flat << "host" << value
      elsif lower == "connection" || forwarding_header?(lower) || lower.start_with?("x-oxo-")
        next
      elsif !lower.include?("_")
        flat << lower << value
      end
    end
    flat
  end

  # Verbatim port of Oxo.build_env (ruby.rs:257-294). `header_flat` is the FILTERED
  # flat [k, v, k, v, ...] list; `server_port` is a STRING (the S1 call site passes
  # `server_port.to_string()`, ruby.rs:112).
  # the empty-body case (every GET) skips the body copy — each request still
  # gets its OWN StringIO (position state), only the frozen backing string is shared.
  # The frozen path skips set_encoding too: EMPTY_BODY is already BINARY, and
  # StringIO#set_encoding may touch the (frozen) backing string.
  EMPTY_BODY = "".b.freeze
  def build_env(method, path, query, server_name, server_port, scheme, remote_addr, multithread, multiprocess, header_flat, body)
    input = if body.empty?
              StringIO.new(EMPTY_BODY)
            else
              io = StringIO.new(body.dup)
              io.set_encoding(Encoding::BINARY)
              io
            end
    env = {
      "REQUEST_METHOD" => method,
      "SCRIPT_NAME" => "",
      "PATH_INFO" => path,
      "QUERY_STRING" => query,
      "SERVER_NAME" => server_name,
      "SERVER_PORT" => server_port,
      "SERVER_PROTOCOL" => "HTTP/1.1",
      "REMOTE_ADDR" => remote_addr,
      "rack.url_scheme" => scheme,
      "rack.input" => input,
      "rack.errors" => $stderr,
      "rack.multithread" => multithread,
      "rack.multiprocess" => multiprocess,
      "rack.run_once" => false
    }
    i = 0
    while i < header_flat.length
      k = header_flat[i]
      v = header_flat[i + 1]
      i += 2
      if k == "content-length"
        env["CONTENT_LENGTH"] = v
      elsif k == "content-type"
        env["CONTENT_TYPE"] = v
      else
        env[HTTP_KEY_TABLE[k] || ("HTTP_" + k.upcase.tr("-", "_"))] = v
      end
    end
    env
  end

  # Port of Oxo.flatten_headers (ruby.rs:296-316, the fix): Rack-3 Array values
  # AND "\n"-joined Rack-2 values both become separate wire lines (an embedded LF would
  # be CTL-rejected wholesale, losing every cookie).
  #
  # B4: emits [name, seg] PAIRS directly — pre-this built a flat array that
  # respond_to_request immediately re-paired via each_slice(2).to_a (a gratuitous
  # allocate-flatten-repair round trip per response). Same expansion rules and order.
  def flatten_header_pairs(headers)
    pairs = []
    headers.each do |k, v|
      key = k.to_s
      # fast path: a plain String value with no embedded LF (the overwhelmingly
      # common case) needs no Array() wrap, no split, no per-segment loop. Expansion
      # rules unchanged for everything else.
      if v.is_a?(String) && !v.include?("\n")
        pairs << [key, v]
        next
      end
      Array(v).each do |vv|
        segs = vv.to_s.split("\n")
        segs << "" if segs.empty? # a legitimately empty value stays one (empty) line
        segs.each do |seg|
          next if seg.empty? && segs.length > 1 # drop spurious empties from "a\n\nb"/"a\n"
          pairs << [key, seg]
        end
      end
    end
    pairs
  end

  # Port of the S1 frame worker's response hygiene (frame.rs:279-304): framing headers
  # are the host's to own; CTL names/values are dropped (loudly) to prevent splitting.
  #
  # the per-byte checks run as C-level regexes on the (overwhelmingly common)
  # ascii_only? strings — the pre-each_byte.all? blocks were the single largest
  # interpreter cost in the banked profile (rb_yield 69% / rb_ary_each 56% children).
  # Non-ASCII strings keep the byte loop: matching an /n regex against a UTF-8 string
  # with high bytes raises Encoding::CompatibilityError, and force_encoding on an
  # app-owned (possibly frozen) string is never acceptable. Same accept/drop sets.
  FRAMING_RESPONSE_HEADERS = %w[content-length transfer-encoding connection].freeze
  VALID_NAME_RE = /\A[\x21-\x7e]+\z/n
  VALID_VALUE_ASCII_RE = /\A[\x09\x20-\x7e]*\z/n
  def sanitize_response_headers(pairs)
    pairs.select do |name, value|
      lower = name.downcase
      next false if FRAMING_RESPONSE_HEADERS.include?(lower)

      valid_name = if name.ascii_only?
                     VALID_NAME_RE.match?(name)
                   else
                     !name.empty? && name.each_byte.all? { |b| b > 0x20 && b < 0x7f }
                   end
      valid_value = if value.ascii_only?
                      VALID_VALUE_ASCII_RE.match?(value)
                    else
                      value.each_byte.all? { |b| b == 0x09 || (b != 0x7f && b >= 0x20) }
                    end
      unless valid_name && valid_value
        warn "oxo-async-worker: dropping response header #{name.inspect}: invalid name or value"
        next false
      end
      true
    end
  end

  # ---- 0xBF codec (mirrors hop_frame.rs Cursor / encode_response) ----

  class Cur
    def initialize(buf)
      @buf = buf
      @pos = 0
    end

    def take(n)
      raise "truncated" if @pos + n > @buf.bytesize
      out = @buf.byteslice(@pos, n)
      @pos += n
      out
    end

    def u8 = take(1).unpack1("C")
    def u16 = take(2).unpack1("v")   # little-endian u16
    def u32 = take(4).unpack1("V")   # little-endian u32
    def short_str = take(u16).force_encoding("UTF-8")
    def long_str = take(u32).force_encoding("UTF-8")
  end

  # Decode a request ENVELOPE (the remaining_length bytes after the 6-byte prefix)
  # -> a hash of the RequestFrame fields. Raises on any malformation (decode-error class).
  def decode_request_envelope(envelope)
    c = Cur.new(envelope)
    method = c.short_str
    path = c.long_str
    query = c.long_str
    server_name = c.short_str
    port = c.u16
    scheme_byte = c.u8
    raise "bad scheme #{scheme_byte}" unless scheme_byte <= 1
    remote_addr = c.short_str
    hcount = c.u16
    raise "too many headers" if hcount > MAX_HEADERS
    headers = Array.new(hcount) { [c.short_str, c.long_str] }
    blen = c.u32
    raise "body over cap" if blen > MAX_BODY_BYTES
    body = c.take(blen)
    {
      method: method, path: path, query: query, server_name: server_name,
      server_port: port, scheme: scheme_byte == 1 ? "https" : "http",
      remote_addr: remote_addr, headers: headers, body: body
    }
  end

  # Encode ONE Full response frame (status + sanitized headers + whole body).
  #
  # B5: single-buffer build — the M0 fix the Rust encoder already has, ported.
  # Pre-this built the envelope in one string and then COPIED it whole into the
  # frame; now the frame is built directly with a 4-byte length placeholder patched at
  # the end. Wire bytes identical.
  # `frame` may be a caller-owned reusable buffer — STRICTLY the happy path of
  # the connection's owning fiber (handle_conn's per-connection buffer). Error/drain
  # frames (encode_error_frame) always take the fresh-string default: the drain fiber
  # writes 500 frames concurrently with app fibers, and a shared buffer there would
  # cross-fiber-corrupt frames on write backpressure.
  def encode_full_response(status, resp_headers, body, frame = +"".b)
    frame.clear
    frame << [FRAME_MAGIC, FRAME_VERSION].pack("C2")
    frame << "\x00\x00\x00\x00".b    # envelope length, patched below
    frame << [0].pack("C")           # RESP_FULL (hop_frame.rs:142)
    frame << [status].pack("v")      # u16-LE status
    frame << [resp_headers.length].pack("v")
    resp_headers.each do |name, value|
      frame << [name.bytesize].pack("v") << name.b
      frame << [value.bytesize].pack("V") << value.b
    end
    frame << [body.bytesize].pack("V") << body.b
    frame[2, 4] = [frame.bytesize - FRAME_PREFIX_LEN].pack("V")
    frame
  end

  ERROR_FRAME_BODY = "Internal Server Error"

  def encode_error_frame
    encode_full_response(500, [["content-type", "text/plain"]], ERROR_FRAME_BODY)
  end

  # ---- app hosting ----

  @app = nil
  @executor = nil

  def load_app(path, lint: ENV["OXO_WORKER_RACK_LINT"] == "1")
    loaded = Rack::Builder.parse_file(path)
    app = loaded.is_a?(Array) ? loaded.first : loaded
    @app = lint ? Rack::Lint.new(app) : app
    # Rails executor wrap (the B0-proven path): reload guards, AR connection release,
    # CurrentAttributes reset — per request, per fiber.
    @executor = defined?(Rails) && Rails.respond_to?(:application) && Rails.application ? Rails.application.executor : nil
    # Boot assertion: a fiber worker over :thread isolation cross-bleeds per-request
    # state between fibers sharing the reactor thread. Fail LOUDLY at boot, not as a
    # data-corruption heisenbug under load. (Bare Rack apps without ActiveSupport skip.)
    # Read the isolation level from ActiveSupport::IsolatedExecutionState, NOT from
    # `ActiveSupport.isolation_level` — that method does not exist (Rails 8.1:
    # `ActiveSupport.respond_to?(:isolation_level) == false`), so the original guard's
    # respond_to? arm was always false and this assertion could NEVER fire. It read as a
    # boot-time safety net through all of M2 while being dead code; the M2 suites never caught
    # it because none of them boots a :thread-isolated app. The rehearsal now runs that case as
    # a POSITIVE control: a :thread boot must abort here.
    if defined?(ActiveSupport::IsolatedExecutionState)
      level = ActiveSupport::IsolatedExecutionState.isolation_level
      if level != :fiber
        abort "oxo-async-worker: ActiveSupport isolation_level=#{level.inspect}, need " \
              ":fiber — set OXO_ASYNC=1 before the app loads (this worker sets it; " \
              "something overrode isolation after)"
      end
    end
    true
  end

  def call_app(env)
    if @executor
      @executor.wrap { @app.call(env) }
    else
      @app.call(env)
    end
  end

  # CONTRACT 1 is upheld by the CALL ORDER here: decode completed before this runs.
  # Returns the encoded response frame bytes for one decoded request.
  def respond_to_request(req, out_buf = +"".b)
    flat = filtered_flat_headers(req[:headers])
    env = build_env(
      req[:method], req[:path], req[:query], req[:server_name],
      req[:server_port].to_s, req[:scheme], req[:remote_addr],
      false, # rack.multithread: one reactor thread (fibers are not threads)
      MULTIPROCESS, # rack.multiprocess: true iff spawned as one of N sibling reactors (B2)
      flat, req[:body]
    )
    status, headers, body = call_app(env)
    body_bytes = collect_body(body)
    resp_headers = sanitize_response_headers(flatten_header_pairs(headers))
    encode_full_response(Integer(status), resp_headers, body_bytes, out_buf)
  end

  # Rack-3 body collection (the ONE thing reused from the legacy helper's shape): each
  # over parts, force BINARY, close if closable. The whole body is buffered — B1 writes
  # ONE Full frame per response (streaming is out of scope until B3+).
  def collect_body(body)
    buf = +"".b
    if body.respond_to?(:each)
      body.each { |part| buf << part.to_s.b }
    else
      # Rack 3 allows a callable-only body; drain it through a writer shim.
      writer = Object.new
      writer.define_singleton_method(:write) { |s| buf << s.to_s.b; s.to_s.bytesize }
      writer.define_singleton_method(:<<) { |s| buf << s.to_s.b; writer }
      writer.define_singleton_method(:flush) { writer }
      writer.define_singleton_method(:close) {}
      body.call(writer)
    end
    body.close if body.respond_to?(:close)
    buf
  end
end

# ---- W1: supervisor conformance (drain registry + verified socket hygiene) ----

# Tracks every live server-mode connection and its phase for the bounded drain:
#   :idle    — parked pre-request (contract 3); closed immediately at drain start
#              (safe: the supervisor TERMs the edge FIRST, so pooled idles already saw
#              the edge's close or are about to — contract 3 is about steady state)
#   :in_app  — dispatched, no response bytes yet; drain-expiry writes the 500 error
#              frame here, moving the loss into the committed-bytes class the edge
#              NEVER retries (the W0 zero-replay contract's other half)
#   :writing — response bytes may be on the wire; drain-expiry closes bare (an
#              appended frame would corrupt a partial response — contract 2's rule)
# One reactor thread, fiber-per-connection: fibers yield only at IO, so no mutex.
class ConnRegistry
  def initialize
    @conns = {}
    @draining = false
  end

  # Once draining, a fiber that COMPLETES its current response must close instead of
  # re-parking in the keepalive read — otherwise the reactor never finishes and the
  # supervisor's TERM stage always escalates to the KILL sweep.
  def start_drain!
    @draining = true
  end

  def draining?
    @draining
  end

  def register(socket)
    @conns[socket] = :idle
  end

  def busy(socket)
    @conns[socket] = :in_app
  end

  def writing(socket)
    @conns[socket] = :writing
  end

  def idle(socket)
    @conns[socket] = :idle
  end

  def unregister(socket)
    @conns.delete(socket)
  end

  def in_flight_count
    @conns.count { |_, state| state != :idle }
  end

  def size = @conns.size

  def close_idle!
    @conns.each do |sock, state|
      next unless state == :idle
      begin
        sock.close
      rescue StandardError
        nil
      end
    end
  end

  # Drain-deadline expiry: abandoned in-flight connections get the encoded 500 error
  # frame (except :writing — see above), then close. Returns the abandoned count.
  def abandon_in_flight!
    abandoned = 0
    @conns.each do |sock, state|
      next if state == :idle
      abandoned += 1
      if state == :in_app
        begin
          sock.write(OxoAsync.encode_error_frame)
          sock.flush
        rescue StandardError
          nil
        end
      end
      begin
        sock.close
      rescue StandardError
        nil
      end
    end
    abandoned
  end
end

# (W1, G7 + panel MED-9) The SERVICE owns runtime-dir creation; the worker only
# VERIFIES — the S1 worker's prepare_socket semantics (serve.rs:54-104) ported:
#   * the parent dir must exist (the supervisor creates + chmods it 0700) and must not
#     be group/other-accessible — REFUSED, not chmodded into compliance: a permissive
#     dir is an operator error to surface, not paper over (the old code's chmod was a
#     hygiene downgrade vs the classic worker)
#   * a stale socket path is unlinked only if it IS a socket and we own it
def prepare_socket_verified(socket_path)
  parent = File.dirname(socket_path)
  unless File.directory?(parent)
    abort("oxo-async-worker: socket parent #{parent} does not exist (the service creates it)")
  end
  mode = File.stat(parent).mode & 0o777
  if (mode & 0o077) != 0
    abort(format("oxo-async-worker: socket parent %s is group/other-accessible (%04o); refusing (want 0700)",
                 parent, mode))
  end
  return unless File.exist?(socket_path)

  st = File.lstat(socket_path)
  unless st.socket?
    abort("oxo-async-worker: #{socket_path} exists and is not a socket; refusing to unlink")
  end
  unless st.uid == Process.euid
    abort("oxo-async-worker: #{socket_path} owned by uid #{st.uid}, not #{Process.euid}; refusing to unlink")
  end
  File.unlink(socket_path)
end

# ---- the per-connection keepalive loop (server mode) ----

# Read exactly n bytes; nil on clean EOF at a frame boundary (pos == 0), raise on
# truncation mid-frame. Under the async reactor a blocked read YIELDS this fiber.
def read_exact(socket, n, buf = nil)
  # `buf` reuses a caller-owned accumulator (the fixed-size prefix only — see
  # handle_conn's aliasing note). Semantics unchanged: nil on clean EOF at a frame
  # boundary (nothing accumulated), raise on truncation mid-frame.
  buf = buf ? buf.clear : +"".b
  while buf.bytesize < n
    chunk = socket.read(n - buf.bytesize)
    if chunk.nil? || chunk.empty?
      return nil if buf.empty?
      raise "truncated read (#{buf.bytesize}/#{n})"
    end
    buf << chunk
  end
  buf
end

# ---- : the tail-hunt timing ledger (env-gated; OFF costs one nil check) ----------
#
# Armed by OXO_WORKER_TIMING_DIR (reaches the worker via the OXO_APP_ENV_ALLOW
# extension, like OXO_BENCH_MIX_STATS_DIR). When armed, each request records:
#   sched  — edge frame-stamp (x-oxo-ts0, CLOCK_MONOTONIC ns) -> first post-decode
#            instant: dispatch-to-fiber-running delay, the quantity invisible from
#            either side alone [panel C1].
#   work   — decode-done -> response frame built (app + encode).
#   write  — frame built -> socket flushed (backpressure separated from work [C8]).
# plus per-request GC bracketing [C3]: GC.count / major count / GC.total_time deltas;
# work samples split into gc/nogc histograms so pause-shaped evidence survives.
# Dumps NEVER run in a reactor fiber [C4]: a dedicated native Thread writes
# timing-<pid>.json (tmp+rename) every 5 s and once at exit.
module OxoTiming
  BUCKETS = 26 # floor(log2 ns), mirroring the edge's hop-timing shape
  # R1: joint-reservoir constants — the tail edge (2^23 ns ~ 8.39 ms,
  # matching histogram bucket 23) and the per-reactor sample cap. At the
  # measured tail rates (~10% sched, ~6% work over ~90k requests/cell) the
  # cap fills in well under a cell; "dropped" counts keep the census honest.
  # env-configurable, exactly as the middleware's OXO_TRACE_TAIL_NS
  # already is. The default is unchanged (2^23 ns ~ 8.39 ms); sets 2 ms, because
  # the question is the shape of a ~1 ms service and an 8.4 ms floor samples almost
  # none of it. A lower floor fills the reservoir far faster, which is why the heavy
  # dump moved out of the periodic thread (see dump).
  TAIL_NS = Integer(ENV.fetch("OXO_WORKER_TAIL_NS", (1 << 23).to_s))
  TAIL_RESERVOIR_CAP = 6000

  # linear bins with exact sums — 64 us wide to 32.768 ms, the shape
  # shipped in the edge (hop_timing::Linear), with a saturating top bin that reports
  # its own mass AND its own sum so a percentile read from the bins is bounded rather
  # than open. The log2 buckets above cannot answer this segment's question: they are a
  # factor of two wide and bucket 19 = [0.524, 1.049) ms straddles the ~0.97 ms mean
  # service, so neither a percentile nor a second moment survives the bracket. Kept
  # BESIDE the log2 arrays, never instead of them, so every banked comparison still
  # reads.
  LIN_BINS = 512
  LIN_BIN_US = 64
  LIN_BIN_NS = LIN_BIN_US * 1_000
  # service      prefix read returned -> socket flushed: the worker's whole service
  #              time at the vantage the edge's exchange span meets (the headline).
  # service_cpu  this thread's CPU over the SAME two endpoints. Under fibers a
  #              sibling's CPU accrues on this thread while this request is suspended,
  #              so service - service_cpu is a LOWER BOUND on the time the thread was
  #              not running this request, not a measurement of "waiting".
  # read_decode  prefix returned -> decode done; work_nogc/work_gc  decode -> frame
  #              built, split by whether a collection landed in the span;
  #              write        frame built -> flushed.
  LINEAR_BLOCKS = %w[service service_cpu read_decode work_nogc work_gc write].freeze

  # the CONSECUTIVE-request ring.
  #
  # inferred a correlated component from a p50->p99 SPREAD residual: 1.600 ms of the
  # 4.960 ms depth-7 spread that a sum of independent service draws cannot produce. That is an
  # inference from marginals. The covariance it is made of can be measured directly, but only
  # from requests in ORDER -- and the tail reservoir cannot supply that, because uniform
  # sampling over the tail destroys adjacency by construction. So this is a ring of every
  # request in sequence, in the shape 's OxoOrder ring already proved cheap at full
  # rate: preallocated Integer arrays written by index, no per-request allocation, and
  # INCREMENTAL BINARY APPENDS -- never JSON of the whole ring, which is the stall found
  # and moved out of the 5 s dumper.
  #
  # Record: three little-endian u32 per request -- service ns, off-CPU ns (service minus the
  # thread CPU over the same two endpoints), and a meta word (GC events in the low byte, flags
  # above). u32 of nanoseconds spans 4.29 s, far past anything a 1 ms service reaches; a value
  # beyond it saturates and is COUNTED, so the analyzer can refuse rather than read a wrapped
  # value as a short request. 12 bytes per request is about 1.6 MB per worker per cell.
  RING_CAP = 65_536
  RING_U32_MAX = (1 << 32) - 1
  RING_FLAG_GC = 1        # a collection landed in this request's span
  RING_FLAG_SAMPLED = 2   # this request also carries a sampled schedstat pair

  # the schedstat subsample. Reading /proc/self/schedstat at both ends of every request
  # would add two file reads to a ~16.6-syscall request (about +12%), which no overhead gate
  # would survive. On 1 request in N it costs 2/N reads per request and is priced by its own
  # arm rather than assumed cheap. N=1 disables sampling; the default is off.
  SCHED_SAMPLE_N = Integer(ENV.fetch("OXO_WORKER_SCHED_SAMPLE_N", "0"))

  class << self
    attr_reader :dir

    def arm!
      @dir = ENV["OXO_WORKER_TIMING_DIR"]
      return unless @dir

      @sched = Array.new(BUCKETS, 0)
      @work_nogc = Array.new(BUCKETS, 0)
      @work_gc = Array.new(BUCKETS, 0)
      @write = Array.new(BUCKETS, 0)
      # iteration 3: the wall-vs-CPU discriminator. work_cpu buckets the request's
      # own THREAD-CPU time inside the work interval; tail_cpu buckets CPU only for
      # requests whose work WALL landed in the tail (>= bucket 23, ~8.4 ms) -- if tail
      # requests show normal CPU, the wall tail is interleaving/scheduling, not work.
      @work_cpu = Array.new(BUCKETS, 0)
      @tail_cpu = Array.new(BUCKETS, 0)
      # R1: the joint tail reservoir. Marginal histograms cannot answer
      # E[ingredient | tail] (panel F1); this records the RAW tuple for every
      # request whose work wall OR dispatch wait exceeds ~8 ms (bucket >= 23),
      # capped, with a monotonic timestamp so the analyzer can assign each
      # sample to its bench rung (panel F2). Keys are compact: t=t_read stamp,
      # s=sched, w=work wall, c=thread-cpu-over-span (UPPER bound on own CPU,
      # panel F3), g=gc events in span, gn=gc ns in span, wr=write ns.
      @tail_samples = []
      @tail_seen = 0
      # one linear block per span (see LINEAR_BLOCKS).
      @linear = LINEAR_BLOCKS.to_h { |name| [name, new_linear] }
      # the consecutive ring (see RING_CAP) and the schedstat subsample.
      @ring_service = Array.new(RING_CAP, 0)
      @ring_offcpu = Array.new(RING_CAP, 0)
      @ring_meta = Array.new(RING_CAP, 0)
      @ring_n = 0
      @ring_dumped = 0
      @ring_lost = 0
      @ring_sat = 0
      @samp_seq = 0
      @samp_idx = []
      @samp_delay = []
      @samp_slices = []
      @samp_dumped = 0
      # voluntary vs non-voluntary context switches. THE discriminator this segment
      # turns on: a thread that blocks yields voluntarily, a thread that is preempted does
      # not. Read once per 5 s dump from /proc/self/status, so the counts are nested INSIDE
      # the measured window -- unlike 's run_delay ratio, which compared a whole-cell
      # counter against a sum taken only inside requests and so could not separate the two.
      @switch0 = read_switches
      @switches = @switch0
      # the PREVIOUS dump's cost, carried into the next series point. A dump that
      # pauses the process is indistinguishable from the correlated stall this segment is
      # trying to detect, so the instrument reports its own cost rather than leaving it to
      # be assumed -- and it reports TWO numbers, because they mean different things:
      #
      #   cpu   the dumper thread's own CPU across the dump. This is the part that holds
      #         the GVL and can actually stall the reactor, so this is what a refusal keys
      #         on. (Ruby releases the GVL around the write and rename syscalls.)
      #   wall  elapsed time across the same span. On a saturated 2-core guest this
      #         INCLUDES the dumper thread's own wait for a core -- s1 measured 6 ms
      #         of wall against a fraction of a millisecond of CPU -- so a wall figure is
      #         a statement about the guest's contention, NOT about how long the reactor
      #         was blocked. Reading it as the latter would refuse every honest cell.
      @dump_hold_ns = nil
      @dump_cpu_ns = nil
      # R1: a small counter time-series (one point per dump) so cumulative
      # counters can be differenced against rung boundaries from outside.
      @series = []
      @counters = { "requests" => 0, "no_stamp" => 0, "gc_events" => 0,
                    "major_gc_events" => 0, "gc_time_ns" => 0, "dump_failures" => 0,
                    "tail_samples_dropped" => 0,
                    # how many requests carried the hoisted service stamp, and the
                    # worst cost any single dump took -- CPU (the GVL-holding part) beside
                    # wall (which on a contended guest is mostly the dumper's own wait for
                    # a core). See @dump_cpu_ns.
                    "service_recorded" => 0, "dumps" => 0,
                    # The two maxima are kept SEPARATE by payload, because only one of
                    # them lands inside the measured window: the light dumps run every 5 s
                    # while requests are being served, and the heavy one runs at the end of
                    # the drain, after the listener is closed. Scoring the heavy dump's cost
                    # against an in-window bound would refuse a cell for a cost no request
                    # ever paid.
                    "dump_hold_max_ns" => 0, "dump_cpu_max_ns" => 0,
                    "full_dumps" => 0, "full_dump_cpu_ns" => 0,
                    "full_dump_wall_ns" => 0 }
      # EXACT nanosecond totals beside the log2 histograms. The buckets are
      # each a factor of two wide, so a mean recovered from them carries ~20%
      # error -- fine for shape, useless for the subtraction this segment needs
      # (response_read minus the worker's own service time, two ~2 ms quantities
      # whose difference is the quantity of interest). The edge already keeps
      # exact count+sum per seam; this gives the worker the same footing. Sums
      # and counts are integers, so they add without loss.
      @sums = { "sched_ns" => 0, "work_ns" => 0, "write_ns" => 0,
                "sched_n" => 0, "work_n" => 0, "write_n" => 0,
                # the same sums restricted to requests that were ALONE on
                # this worker. The edge already reports exchange time bucketed by
                # dispatch depth, but subtracting an all-requests work mean from
                # a depth-0 exchange mean compares two different populations --
                # depth-0 requests are selected for arriving at an idle worker.
                # A worker knows its own concurrency, so it can bucket its own
                # work the same way, and the subtraction becomes like-for-like.
                "work_solo_ns" => 0, "work_solo_n" => 0,
                "write_solo_ns" => 0, "write_solo_n" => 0,
                # EXACT thread-CPU sums beside the log2 work_cpu histogram.
                # The histogram's buckets are each a factor of two wide, so the
                # mean it supports is only bounded to within a factor of two --
                # and 's question is whether one queue position costs one
                # predecessor's service time or MORE than it, a distinction
                # smaller than a single bucket. Bounds cannot answer it; an
                # exact sum can.
                "work_cpu_ns" => 0, "work_cpu_n" => 0,
                "work_cpu_solo_ns" => 0, "work_cpu_solo_n" => 0 }
      # the OS run-queue split. The two candidate mechanisms for the
      # in-worker wait -- sibling fibers waiting for this reactor, and the
      # reactor itself waiting for a CPU -- are the same queue at two layers, so
      # a wait measurement alone cannot separate them. The kernel already
      # accounts the second one: field 2 of /proc/self/schedstat is this thread's
      # cumulative run_delay, the nanoseconds it spent runnable but not running.
      # The reactor is the process's main thread, so /proc/self/schedstat is its
      # own. Sampled cumulatively, differenced from the first reading.
      @sched_stat0 = read_schedstat
      @sched_stat = @sched_stat0
      GC.measure_total_time = true if GC.respond_to?(:measure_total_time=)
      # Clock self-test: monotonic must advance; cross-process validity holds by
      # construction (same clock id, same boot) — recorded in the dump meta.
      a = now_ns
      b = now_ns
      abort("oxo-async-worker: monotonic clock not advancing") if b < a
      warn "oxo-async-worker: timing armed dir=#{@dir} pid=#{Process.pid}"
      # the periodic thread writes the LIGHT payload only (counters + series);
      # the heavy payload is serialized once, at exit. See dump.
      @dumper = Thread.new do
        loop do
          sleep 5
          dump
        end
      end
      at_exit { dump(full: true) }
    end

    def armed? = !@dir.nil?

    def now_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)

    def cpu_ns = Process.clock_gettime(Process::CLOCK_THREAD_CPUTIME_ID, :nanosecond)

    def bucket(ns)
      ns = 1 if ns < 1
      [ns.bit_length - 1, BUCKETS - 1].min
    end

    # a fresh linear block. count and sum are EXACT over every sample (the top
    # bin's overflow is added to sum as well, and separately to over_sum), so a mean
    # read from the block carries no bracket error and can be checked against the mean
    # implied by the bins.
    def new_linear
      { "bin_us" => LIN_BIN_US, "count" => 0, "sum_nanos" => 0,
        "over" => 0, "over_sum_nanos" => 0, "bins" => Array.new(LIN_BINS, 0) }
    end

    # record one sample into a linear block. Integer arithmetic on preallocated
    # arrays — no allocation, no float, roughly the cost of the log2 bucket beside it.
    def lin(name, ns)
      ns = 0 if ns.negative?
      b = @linear[name]
      b["count"] += 1
      b["sum_nanos"] += ns
      i = ns / LIN_BIN_NS
      if i < LIN_BINS
        b["bins"][i] += 1
      else
        b["over"] += 1
        b["over_sum_nanos"] += ns
      end
    end

    # [voluntary, nonvoluntary] context switches for this THREAD GROUP, or nil.
    #
    # nil rather than zeros when the fields are absent, for the same reason read_schedstat
    # returns nil: a kernel that is not reporting looks exactly like a thread that never
    # switched, which is the reading this measurement exists to rule out.
    def read_switches
      vol = nonvol = nil
      File.foreach("/proc/self/status") do |line|
        vol = line.split.last.to_i if line.start_with?("voluntary_ctxt_switches:")
        nonvol = line.split.last.to_i if line.start_with?("nonvoluntary_ctxt_switches:")
      end
      (vol && nonvol) ? [vol, nonvol] : nil
    rescue StandardError
      nil
    end

    # does THIS request carry a sampled schedstat pair? Called once per request from the
    # read loop, so the decision and the opening read happen at the same instant as the
    # service span's start. Returns the triple to close against, or nil.
    def sample_start
      return nil if SCHED_SAMPLE_N < 2

      @samp_seq += 1
      return nil unless (@samp_seq % SCHED_SAMPLE_N).zero?

      read_schedstat
    end

    # one request into the consecutive ring. Integer writes into preallocated arrays --
    # no allocation, so arming the ring does not change the allocation profile this worker is
    # also measured on.
    def record_ring(service_ns, offcpu_ns, gc_events, flags)
      i = @ring_n % RING_CAP
      # Unread records overwritten before a dump: counted, never silently dropped, so the
      # analyzer can refuse on a gap instead of computing a lag over a discontinuity.
      @ring_lost += 1 if @ring_n - @ring_dumped >= RING_CAP
      service_ns = 0 if service_ns.negative?
      offcpu_ns = 0 if offcpu_ns.negative?
      if service_ns > RING_U32_MAX || offcpu_ns > RING_U32_MAX
        @ring_sat += 1
        service_ns = [service_ns, RING_U32_MAX].min
        offcpu_ns = [offcpu_ns, RING_U32_MAX].min
      end
      @ring_service[i] = service_ns
      @ring_offcpu[i] = offcpu_ns
      @ring_meta[i] = (gc_events & 0xff) | (flags << 8)
      @ring_n += 1
      i
    end

    # append the records written since the last append. Binary, sequential, and O(new
    # records) -- the order-ring shape, chosen because measured what happens when a
    # cumulative payload is re-serialized on a timer inside the measured span.
    def dump_ring
      return unless @dir

      n = @ring_n
      from = [@ring_dumped, n - RING_CAP].max
      k = n - from
      if k.positive?
        rec = Array.new(3 * k)
        j = 0
        from.upto(n - 1) do |idx|
          i = idx % RING_CAP
          rec[j] = @ring_service[i]
          rec[j + 1] = @ring_offcpu[i]
          rec[j + 2] = @ring_meta[i]
          j += 3
        end
        File.open(File.join(@dir, "ring-#{Process.pid}.bin"), "ab") { |f| f.write(rec.pack("L<*")) }
      end
      @ring_dumped = n
      sk = @samp_idx.length - @samp_dumped
      if sk.positive?
        rec = Array.new(3 * sk)
        j = 0
        @samp_dumped.upto(@samp_idx.length - 1) do |x|
          rec[j] = @samp_idx[x]
          rec[j + 1] = @samp_delay[x]
          rec[j + 2] = @samp_slices[x]
          j += 3
        end
        File.open(File.join(@dir, "sample-#{Process.pid}.bin"), "ab") { |f| f.write(rec.pack("Q<*")) }
        @samp_dumped = @samp_idx.length
      end
      nil
    rescue StandardError
      @counters["dump_failures"] += 1 if @counters
      nil
    end

    # the sparse form the edge emits — only non-zero bins, keyed by index.
    def linear_json(block)
      sparse = {}
      block["bins"].each_with_index { |v, i| sparse[i.to_s] = v if v.positive? }
      block.merge("bins" => sparse)
    end

    # [run_time_ns, run_delay_ns, timeslices] for THIS thread, or nil.
    #
    # Returns nil rather than zeros when the file is missing or the kernel has
    # schedstats compiled out or switched off (/proc/sys/kernel/sched_schedstats
    # = 0), because a kernel that is not accounting reports a run_delay of
    # exactly 0 -- indistinguishable from a thread that never waited, which is
    # the answer this measurement exists to rule out. The availability flag is
    # written into every dump so an analyzer can refuse rather than read a zero
    # as a finding.
    def read_schedstat
      line = File.read("/proc/self/schedstat").split
      return nil if line.length < 3

      [line[0].to_i, line[1].to_i, line[2].to_i]
    rescue StandardError
      nil
    end

    def schedstat_available?
      return false unless @sched_stat0

      # A kernel with sched_schedstats off leaves run_time at zero as well, so a
      # zero run_time after real work is the tell that nothing is being counted.
      cur = read_schedstat
      !cur.nil? && cur[0] > 0
    end

    def record(ts0, t_read, t_built, t_written, gc_delta, major_delta, gc_time_delta, cpu_delta = nil,
               solo: nil, t_start: nil, c_start: nil, c_end: nil, sched_start: nil)
      @counters["requests"] += 1
      if ts0
        @sched[bucket(t_read - ts0)] += 1
        @sums["sched_ns"] += (t_read - ts0)
        @sums["sched_n"] += 1
      else
        @counters["no_stamp"] += 1
      end
      @sums["work_ns"] += (t_built - t_read)
      @sums["work_n"] += 1
      @sums["write_ns"] += (t_written - t_built)
      @sums["write_n"] += 1
      if solo
        @sums["work_solo_ns"] += (t_built - t_read)
        @sums["work_solo_n"] += 1
        @sums["write_solo_ns"] += (t_written - t_built)
        @sums["write_solo_n"] += 1
      end
      # the linear blocks. t_start is the instant the frame prefix read returned,
      # taken in BOTH read branches (see handle_conn), so the whole service span is
      # available whether or not the order ring is armed.
      service = nil
      if t_start
        service = t_written - t_start
        @counters["service_recorded"] += 1
        lin("service", service)
        lin("read_decode", t_read - t_start)
        lin(gc_delta.positive? ? "work_gc" : "work_nogc", t_built - t_read)
        lin("write", t_written - t_built)
        lin("service_cpu", c_end - c_start) if c_start && c_end
        # the consecutive record. off-CPU is service minus the thread CPU over the SAME
        # two endpoints -- a lower bound on time the thread was not running this request, for
        # the reason registered: a sibling fiber's CPU accrues on this thread and can
        # only shrink the difference.
        if c_start && c_end
          flags = gc_delta.positive? ? RING_FLAG_GC : 0
          flags |= RING_FLAG_SAMPLED if sched_start
          idx = record_ring(service, service - (c_end - c_start), gc_delta, flags)
          if sched_start
            st = read_schedstat
            if st
              @samp_idx << idx
              @samp_delay << (st[1] - sched_start[1])
              @samp_slices << (st[2] - sched_start[2])
            end
          end
        end
      end
      wall_bucket = bucket(t_built - t_read)
      if gc_delta.positive?
        @work_gc[wall_bucket] += 1
        @counters["gc_events"] += gc_delta
        @counters["major_gc_events"] += major_delta
        @counters["gc_time_ns"] += gc_time_delta
      else
        @work_nogc[wall_bucket] += 1
      end
      if cpu_delta
        @work_cpu[bucket(cpu_delta)] += 1
        @tail_cpu[bucket(cpu_delta)] += 1 if wall_bucket >= 23
        @sums["work_cpu_ns"] += cpu_delta
        @sums["work_cpu_n"] += 1
        if solo
          @sums["work_cpu_solo_ns"] += cpu_delta
          @sums["work_cpu_solo_n"] += 1
        end
      end
      @write[bucket(t_written - t_built)] += 1
      # R1: joint reservoir. Sched tail matters as much as work tail —
      # sample on either. TAIL_NS = 2^23 ns (~8.4 ms), the same edge the
      # marginal histograms use, so populations stay comparable.
      # sample on the SERVICE span as well. The headline quantity is service, so
      # a reservoir gated only on work wall would exclude exactly the tuples P4 reads
      # (a service inflated by the read or the write carries a normal work wall).
      sched_ns = ts0 ? t_read - ts0 : nil
      unless (t_built - t_read) >= TAIL_NS || (sched_ns && sched_ns >= TAIL_NS) ||
             (service && service >= TAIL_NS)
        return
      end

      # UNIFORM reservoir sampling (algorithm R). First-N-then-drop clusters the
      # sample in whichever phase produced tail events earliest, which makes any
      # cross-arm or cross-phase comparison invalid without saying so.
      @tail_seen += 1
      # sv = the whole service span, sc = this thread's CPU over the SAME two
      # endpoints. sv - sc is the lower bound on thread-off-CPU time P4 reads; "t" is
      # the monotonic stamp the dump-clustering pre-check joins against the series.
      row = {
        "t" => t_read, "s" => sched_ns, "w" => t_built - t_read,
        "c" => cpu_delta, "g" => gc_delta, "gn" => gc_time_delta,
        "wr" => t_written - t_built,
        "sv" => service, "sc" => (c_start && c_end ? c_end - c_start : nil)
      }
      if @tail_samples.length < TAIL_RESERVOIR_CAP
        @tail_samples << row
      else
        j = rand(@tail_seen)
        if j < TAIL_RESERVOIR_CAP
          @tail_samples[j] = row
        else
          @counters["tail_samples_dropped"] += 1
        end
      end
    end

    # what the HEAVY dump itself cost, in a small sidecar written straight after it.
    #
    # A dump cannot report its own cost: the counters are folded in only after the payload
    # has been serialized, so the heavy dump's own numbers would always read zero in the
    # file it just wrote -- and the heavy dump is the LAST write the process makes, because
    # the supervisor's teardown ladder kills it shortly afterwards (which is why the heavy
    # dump moved into the drain at all). So the cost goes beside the payload instead.
    # Descriptive only, out of the measured window like the dump itself, and never scored;
    # an analyzer that does not find it must not refuse, because the payload is already
    # complete and only this footnote is missing.
    def write_dump_cost
      warn "oxo-async-worker: timing heavy dump written pid=#{Process.pid} " \
           "cpu=#{@dump_cpu_ns}ns wall=#{@dump_hold_ns}ns"
      path = File.join(@dir, "timing-#{Process.pid}-cost.json")
      File.write("#{path}.tmp", JSON.generate({
        "pid" => Process.pid,
        "full_dumps" => @counters["full_dumps"], "dumps" => @counters["dumps"],
        "full_dump_cpu_ns" => @dump_cpu_ns, "full_dump_wall_ns" => @dump_hold_ns,
        "dump_cpu_max_ns" => @counters["dump_cpu_max_ns"],
        "dump_hold_max_ns" => @counters["dump_hold_max_ns"]
      }))
      File.rename("#{path}.tmp", path)
    rescue StandardError
      nil
    end

    # the dump is SPLIT, and it says what it cost.
    #
    # Before this method JSON.generate'd the entire cumulative payload -- every
    # bin array plus the whole 6000-tuple tail reservoir -- every 5 s from a plain Ruby
    # Thread, which holds the GVL for the length of the serialize. That is a periodic
    # multi-millisecond pause of the WHOLE process, landing inside the very span this
    # segment measures, and shaped exactly like the correlated stall it is trying to
    # detect (priced the identically shaped middleware dump at +1.7% rps / +1.2 ms
    # p99, and already avoided it for the order ring with incremental appends).
    # lowers TAIL_NS to 2 ms, which fills the reservoir far faster, so the old
    # shape would have been worse than the one that was priced.
    #
    # So: the periodic thread writes only the small counter series (full: false), and
    # the heavy payload is serialized ONCE, at exit (full: true). Every dump times its
    # own wall hold; the max is a counter and each hold is carried into the next series
    # point, so the analyzer reads what the instrument cost instead of assuming it.
    # An analyzer must REFUSE a dump with full != true -- the heavy payload is what
    # carries the bins, and a light-only file means the worker died without unwinding.
    def dump(full: false)
      return unless @dir

      hold0 = now_ns
      cpu0 = cpu_ns
      path = File.join(@dir, "timing-#{Process.pid}.json")
      tmp = "#{path}.tmp"
      require "json"
      # R1: one series point per dump — cumulative counters plus the
      # tail-relevant exceedance counts, so rung windows can be differenced
      # from outside without full per-rung histograms (panel F2).
      @sched_stat = read_schedstat || @sched_stat
      @switches = read_switches || @switches
      @series << {
        "t" => now_ns,
        "req" => @counters["requests"],
        # cumulative run_delay for the reactor thread, so a rung window can
        # be differenced from outside the same way the request counters are.
        "run_delay_ns" => (@sched_stat && @sched_stat[1]),
        "run_time_ns" => (@sched_stat && @sched_stat[0]),
        "gc_ev" => @counters["gc_events"],
        "gc_ns" => @counters["gc_time_ns"],
        # cumulative, differenced per window by the analyzer the same way `req` is.
        # slices is the third schedstat field, which the ledger has read and discarded since
        # ; it is the thread's switch-in count and the denominator for a per-activation
        # wait.
        "slices" => (@sched_stat && @sched_stat[2]),
        "vol" => (@switches && @switches[0]),
        "nonvol" => (@switches && @switches[1]),
        "ring_n" => @ring_n, "ring_lost" => @ring_lost, "ring_sat" => @ring_sat,
        "samp_n" => @samp_idx.length,
        "sched_hi" => @sched[23..].sum,
        "work_hi" => @work_nogc[24..].sum + @work_gc[24..].sum,
        # the cost of the dump that wrote the PREVIOUS point (this point is built
        # before this dump's own write completes). nil on the first point. cpu is the
        # GVL-holding part; wall on a contended guest is mostly waiting for a core.
        "prev_hold_ns" => @dump_hold_ns,
        "prev_cpu_ns" => @dump_cpu_ns
      }
      @series.shift if @series.length > 400
      payload = {
        "pid" => Process.pid,
        "buckets" => BUCKETS,
        "full" => full,
        # the reservoir floor actually in force, so a cross-cell comparison can
        # refuse rather than silently pool two different tail populations.
        "tail_ns" => TAIL_NS,
        "gc_total_time_supported" => GC.respond_to?(:total_time),
        "counters" => @counters,
        "sums" => @sums,
        # the reactor thread's own OS scheduling account, and whether the
        # kernel is actually keeping one. Deltas from the first reading, so the
        # numbers describe the measured window and not the process's whole life.
        "schedstat_available" => schedstat_available?,
        "run_delay_ns" => (@sched_stat && @sched_stat0 &&
                           (@sched_stat[1] - @sched_stat0[1])),
        "run_time_ns" => (@sched_stat && @sched_stat0 &&
                          (@sched_stat[0] - @sched_stat0[0])),
        "series" => @series, "tail_seen" => @tail_seen,
        # the ring's own census, so the analyzer can require that the binary holds one
        # record per request and refuse when it does not -- a gap breaks adjacency, which is
        # the only thing the ring exists to provide.
        "ring" => { "cap" => RING_CAP, "n" => @ring_n, "dumped" => @ring_dumped,
                    "lost" => @ring_lost, "saturated" => @ring_sat,
                    "record_bytes" => 12, "format" => "L<3" },
        "sched_sample" => { "every" => SCHED_SAMPLE_N, "n" => @samp_idx.length,
                            "record_bytes" => 24, "format" => "Q<3" },
        "switches" => (@switches && @switch0 &&
                       { "vol" => @switches[0] - @switch0[0],
                         "nonvol" => @switches[1] - @switch0[1] })
      }
      if full
        # The heavy half: every bin array and the whole reservoir. Exit only.
        payload["sched"] = @sched
        payload["work_nogc"] = @work_nogc
        payload["work_gc"] = @work_gc
        payload["work_cpu"] = @work_cpu
        payload["tail_cpu"] = @tail_cpu
        payload["write"] = @write
        payload["linear"] = @linear.transform_values { |b| linear_json(b) }
        payload["tail_samples"] = @tail_samples
      end
      dump_ring
      File.write(tmp, JSON.generate(payload))
      File.rename(tmp, path)
      @counters["dumps"] += 1
      @counters["full_dumps"] += 1 if full
      @dump_hold_ns = now_ns - hold0
      @dump_cpu_ns = cpu_ns - cpu0
      if full
        # Out of window by construction (drain end, then exit), and far more expensive:
        # it serializes every bin array and the whole reservoir. Recorded so the cost is
        # visible, never folded into the in-window maxima.
        @counters["full_dump_cpu_ns"] = @dump_cpu_ns
        @counters["full_dump_wall_ns"] = @dump_hold_ns
      else
        if @dump_hold_ns > @counters["dump_hold_max_ns"]
          @counters["dump_hold_max_ns"] = @dump_hold_ns
        end
        if @dump_cpu_ns > @counters["dump_cpu_max_ns"]
          @counters["dump_cpu_max_ns"] = @dump_cpu_ns
        end
      end
      write_dump_cost if full
      nil
    rescue StandardError
      @counters["dump_failures"] += 1 if @counters
    end
  end
end

# ---- : the service-order ring and the fair-read knob (env-gated; both OFF) -------
#
# The question (docs/plans/-fair-read.md): at 2 cores the async arm's tail is
# longer than the classic arm's at the same mean. Candidate: after a response is
# flushed the fiber loops straight back into read; if the closed-loop reply has
# already landed on its connection it serves again WITHOUT passing the selector,
# ahead of the other connections whose frames have been waiting.
#
# OXO_WORKER_ORDER_DIR=<dir> arms a per-request ring: {conn fileno, start ns,
# end ns, flags} in four preallocated Integer arrays (no per-request object). The
# prefix is first tried with read_nonblock, so "present" = the frame was already
# there when the fiber looked. flags: bit 0 present, bit 1 yielded (the fair-read
# path passed the scheduler before this read). Dumps are incremental and binary:
# every 10 s the entries since the last dump are appended to order-<pid>.bin as
# little-endian u64 quads, and a small JSON sidecar records per-dump counts and the
# reactor thread's run-queue delay. Never JSON of the ring (panel C4).
#
# OXO_WORKER_FAIR_READ=<mode>: before each frame read the fiber steps aside so
# the connections the selector finds ready are served before this one looks again
# (: at 2 cores this moved p99 from 23.1 to 16.9 ms with nothing else moving).
# Modes (, docs/plans/-pair-profile.md); anything else refuses at boot:
#   yield2     THE DEFAULT since (docs/plans/-default-yield2.md): two
#              consecutive Fiber.scheduler.yield calls; unset or empty selects it
#   off        the previous shape ("0" as well); the production rollback lever
#   pair       the pair: sleep(0) then Fiber.scheduler.yield ("1" is its alias
#              for the receipts already banked)
#   timerpush  a zero timer whose callback pushes this fiber, then a plain transfer;
#              needs the receipted async / io-event versions (private timer list)
#   sleep0, yield1   single-primitive CONTROLS for the cost profile; they do not give
#              the order and must never be a default
# How the order arises in io-event 1.19 / async 2.42 (read from the source): the
# selector resumes epoll-ready fibers INLINE (a direct transfer), only yielded or
# pushed fibers sit on the ready list, select runs ready_flush first and then an
# unconditional epoll_wait(0), and ready_flush captures the list's tail so a fiber
# that yields during a flush is not resumed again in that flush. The pair: the zero
# timer transfers to the loop, the loop's select serves every ready sibling inline,
# then the timer fires and this fiber yields onto the ready list, flushed next. yield2:
# the first yield lands on the list; at the next flush this fiber runs and yields again
# past the captured tail; epoll_wait(0) then serves the siblings inline; the following
# flush resumes this fiber. IO#wait_readable alone cannot do it: level-triggered epoll
# keeps a fd reported earlier ahead of one whose data arrived later. Placed after the
# idle/draining bookkeeping of the previous request (panel C10); a drain during the
# step is seen at the following read, which raises into the decode-error rescue and
# closes bare.
module OxoOrder
  CAP = 65_536
  FLAG_PRESENT = 1
  FLAG_YIELDED = 2
  FAIR_MODES = %w[off pair yield2 timerpush sleep0 yield1].freeze
  DEFAULT_FAIR_MODE = "yield2" # the measured default (2, 8 and 16 cores)
  FAIR_MODE = begin
    raw = ENV["OXO_WORKER_FAIR_READ"]
    case raw
    when nil, "" then DEFAULT_FAIR_MODE
    when "0", "off" then "off"
    when "1", "pair" then "pair"
    when *FAIR_MODES then raw
    else
      abort("oxo-async-worker: OXO_WORKER_FAIR_READ=#{raw.inspect} is not one of #{FAIR_MODES.join('|')}")
    end
  end
  PINNED_ASYNC = "2.42.0"
  PINNED_IO_EVENT = "1.19.1"

  class << self
    attr_reader :dir

    def arm!
      @dir = ENV["OXO_WORKER_ORDER_DIR"]
      return unless @dir

      require "fileutils"
      FileUtils.mkdir_p(@dir)
      @conn = Array.new(CAP, 0)
      @start = Array.new(CAP, 0)
      @stop = Array.new(CAP, 0)
      @flags = Array.new(CAP, 0)
      @n = 0
      @dumped = 0
      @lost = 0
      @dumps = []
      @dumper = Thread.new do
        loop do
          sleep 10
          dump
        end
      end
      at_exit { dump }
      warn "oxo-async-worker: order armed dir=#{@dir} pid=#{Process.pid} cap=#{CAP}"
    end

    def armed? = !@dir.nil?

    def fair_read? = FAIR_MODE != "off"

    def fair_mode = FAIR_MODE

    # timerpush reaches into the scheduler's private timer list; refuse on any other
    # version than the one the profile and the receipts were taken on. yield2's ORDER
    # effect was validated on that same pair (order table, sessions); on any
    # other pair the API is still safe but the effect is unverified, so the worker warns
    # and receipts validated=0 on its contract line instead of refusing (panel C2).
    def check_mode!
      av = defined?(Async::VERSION) ? Async::VERSION : "?"
      iv = defined?(IO::Event::VERSION) ? IO::Event::VERSION : "?"
      @validated = (av == PINNED_ASYNC && iv == PINNED_IO_EVENT)
      return if @validated || FAIR_MODE == "off"

      if FAIR_MODE == "timerpush"
        abort("oxo-async-worker: fair_read=timerpush needs async #{PINNED_ASYNC} / io-event #{PINNED_IO_EVENT}, running #{av} / #{iv}")
      end
      warn "oxo-async-worker: fair_read=#{FAIR_MODE} was validated on async #{PINNED_ASYNC} / io-event #{PINNED_IO_EVENT}, " \
           "running #{av} / #{iv}: the order effect is unverified here (validated=0)"
    end

    def validated? = @validated.nil? ? true : @validated

    # Per-connection state for the fair step, built inside the connection's fiber.
    def fair_context
      return nil unless FAIR_MODE == "timerpush"

      sched = Fiber.scheduler
      fiber = Fiber.current
      timers = sched.instance_variable_get(:@timers)
      cb = proc { sched.push(fiber) if fiber.alive? }
      [sched, timers, cb]
    end

    def fair_step(ctx)
      @fair_reads += 1
      case FAIR_MODE
      when "pair"
        sleep(0)
        Fiber.scheduler.yield
      when "yield2"
        Fiber.scheduler.yield
        Fiber.scheduler.yield
      when "timerpush"
        sched, timers, cb = ctx
        handle = timers.after(0, &cb)
        begin
          sched.transfer
        rescue Exception # rubocop:disable Lint/RescueException -- cancel the timer on any unwind (Async::Stop included), then re-raise
          begin
            handle.cancel!
          rescue StandardError
            nil
          end
          raise
        end
      when "sleep0"
        sleep(0)
      when "yield1"
        Fiber.scheduler.yield
      end
    end

    # hot-path counters (integers only): printed once at exit so every cell
    # carries them without the ring.
    def count_request(registry_size)
      @requests += 1
      @registry_sum += registry_size
      @registry_max = registry_size if registry_size > @registry_max
    end

    def install_counters!
      @requests = 0
      @fair_reads = 0
      @registry_sum = 0
      @registry_max = 0
      at_exit do
        gc_ns = GC.respond_to?(:total_time) ? GC.total_time : -1
        warn "oxo-async-worker: fair counters mode=#{FAIR_MODE} requests=#{@requests} fair_reads=#{@fair_reads} " \
             "registry_sum=#{@registry_sum} registry_max=#{@registry_max} gc_count=#{GC.count} gc_ns=#{gc_ns} pid=#{Process.pid}"
      end
    end

    def now_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)

    def record(conn, start_ns, end_ns, flags)
      i = @n % CAP
      @lost += 1 if @n - @dumped >= CAP
      @conn[i] = conn
      @start[i] = start_ns
      @stop[i] = end_ns
      @flags[i] = flags
      @n += 1
    end

    def read_schedstat
      line = File.read("/proc/self/schedstat").split
      return nil if line.length < 3

      [line[0].to_i, line[1].to_i, line[2].to_i]
    rescue StandardError
      nil
    end

    def dump
      return unless @dir

      n = @n
      from = [@dumped, n - CAP].max
      k = n - from
      if k.positive?
        rec = Array.new(4 * k)
        j = 0
        from.upto(n - 1) do |idx|
          i = idx % CAP
          rec[j] = @conn[i]
          rec[j + 1] = @start[i]
          rec[j + 2] = @stop[i]
          rec[j + 3] = @flags[i]
          j += 4
        end
        File.open(File.join(@dir, "order-#{Process.pid}.bin"), "ab") { |f| f.write(rec.pack("Q<*")) }
      end
      @dumped = n
      st = read_schedstat
      # wall_ms beside the monotonic stamp: the analyzer maps ring entries to the
      # bench's pass windows (unix ms) through the nearest dump's pair.
      @dumps << { "t" => now_ns, "wall_ms" => (Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)),
                  "n" => n, "lost" => @lost,
                  "run_delay_ns" => (st && st[1]), "run_time_ns" => (st && st[0]) }
      @dumps.shift if @dumps.length > 2000
      require "json"
      path = File.join(@dir, "order-#{Process.pid}.json")
      tmp = "#{path}.tmp"
      File.write(tmp, JSON.generate({
        "pid" => Process.pid, "cap" => CAP, "fair_read" => FAIR_MODE,
        "async" => (defined?(Async::VERSION) ? Async::VERSION : nil),
        "io_event" => (defined?(IO::Event::VERSION) ? IO::Event::VERSION : nil),
        "dumps" => @dumps
      }))
      File.rename(tmp, path)
    rescue StandardError
      nil
    end
  end
end

def handle_conn(socket, registry = nil)
  # per-connection reusable buffers, owned exclusively by this fiber:
  # - prefix_buf: the fixed 6-byte frame prefix (consumed before the next read).
  # - out_buf: the response frame (socket.write completes — or the connection dies —
  #   before the next iteration reuses it; drain/error frames never touch it).
  # The ENVELOPE stays a fresh string by design: decoded header/body slices alias it
  # via byteslice (CoW), and refilling an aliased buffer forces an unshare-copy that
  # refunds the reuse (panel C8).
  prefix_buf = +"".b
  out_buf = +"".b
  timing = OxoTiming.armed? # cached once; the OFF path costs this one check
  order = OxoOrder.armed? # cached once, same discipline
  stamp = timing || order # either instrument needs the post-prefix-read instant
  fair = OxoOrder.fair_read?
  fair_ctx = fair ? OxoOrder.fair_context : nil # built inside this fiber
  loop do
    # CONTRACT 3: no read timeout — an idle pooled connection blocks here forever;
    # only the edge retires idles. nil = clean EOF at a frame boundary (edge closed).
    # Any mid-frame EOF/short read, bad magic/version, oversized declared length, or
    # envelope malformation is the decode-error class (contract 1b): close with no app
    # call and no bytes written — the legal pre-dispatch zero-byte-EOF class.
    yielded = false
    present = false
    t_start = nil
    c_start = nil # thread CPU at the same instant as t_start
    sched_start = nil # schedstat at that instant, on the 1-in-N subsample
    req = begin
      # fair read (see the module comment for why this pair): the zero sleep
      # returns after the selector has queued every ready sibling, the yield puts
      # this fiber behind them, so a frame that landed during the last response
      # does not jump the connections that have been waiting.
      if fair
        OxoOrder.fair_step(fair_ctx)
        yielded = true
      end
      if order
        # present-detection: read_nonblock never enters the scheduler. Any bytes
        # (even a short prefix) mean the frame was already there; the remainder, if
        # any, completes through the ordinary read (panel C8).
        first = socket.read_nonblock(FRAME_PREFIX_LEN, prefix_buf, exception: false)
        if first == :wait_readable
          prefix = read_exact(socket, FRAME_PREFIX_LEN, prefix_buf)
        elsif first.nil?
          prefix = nil
        else
          present = true
          prefix = prefix_buf
          if prefix.bytesize < FRAME_PREFIX_LEN
            rest = read_exact(socket, FRAME_PREFIX_LEN - prefix.bytesize)
            raise "truncated read (#{prefix.bytesize}/#{FRAME_PREFIX_LEN})" if rest.nil?

            prefix << rest
          end
        end
      else
        prefix = read_exact(socket, FRAME_PREFIX_LEN, prefix_buf)
      end
      # the service span's start instant — the frame prefix has arrived and this
      # fiber is running — taken in BOTH read branches. Before this stamp existed
      # only inside the `order` branch, and arming that branch also swaps read_exact
      # for the read_nonblock present-detection path: an extra syscall per request, on
      # an instrument that failed its own overhead gate twice at about -1.4% rps
      # (/). Reading the clock here costs one vDSO clock_gettime (~25 ns) when
      # stamping is armed and leaves the read strategy byte-identical either way, so
      # arming the timing ledger can no longer change how frames are read.
      if stamp
        t_start = OxoTiming.now_ns
        if timing
          c_start = OxoTiming.cpu_ns
          # the decision and the opening read happen at the SAME instant as the service
          # span's start, so a sampled request's run_delay covers exactly the span its
          # off-CPU time is measured over.
          sched_start = OxoTiming.sample_start
        end
      end
      break if prefix.nil?
      OxoOrder.count_request(registry ? registry.size : 0) # counters
      break unless prefix.getbyte(0) == FRAME_MAGIC && prefix.getbyte(1) == FRAME_VERSION
      remaining = prefix.byteslice(2, 4).unpack1("V")
      break if remaining > MAX_REMAINING
      envelope = read_exact(socket, remaining)
      break if envelope.nil?
      OxoAsync.decode_request_envelope(envelope)
    rescue StandardError
      break # decode-error class: no app call, no bytes written
    end

    # timing hooks (armed only): the decode is done, the fiber is running.
    if timing
      t_read = OxoTiming.now_ns
      ts0_pair = req[:headers].find { |n, _| n == "x-oxo-ts0" }
      ts0 = ts0_pair && ts0_pair[1].to_i
      gc_c0 = GC.count
      gc_m0 = GC.stat(:major_gc_count)
      gc_t0 = GC.respond_to?(:total_time) ? GC.total_time : 0
      cpu0 = OxoTiming.cpu_ns
    end

    # ---- dispatch boundary: from here CONTRACT 2 owns every exit ----
    registry&.busy(socket) # W1: drain-visible — an abandoned :in_app conn gets a 500 frame
    # is this request ALONE on this worker? busy() has already counted it,
    # so a count of 1 means nothing else is in flight here. Recorded only when
    # timing is armed, and it is a plain count over a small hash on a path that
    # already walks it for drain visibility.
    solo = timing ? (registry.nil? || registry.in_flight_count == 1) : nil
    wrote_response = false
    begin
      frame = OxoAsync.respond_to_request(req, out_buf)
      t_built = OxoTiming.now_ns if timing
      wrote_response = true # the write below either sends the whole frame or raises
      registry&.writing(socket) # W1: past here a drain-expiry close is BARE (no appended frame)
      socket.write(frame)
      socket.flush
      if order
        OxoOrder.record(socket.fileno, t_start, OxoOrder.now_ns,
                            (present ? OxoOrder::FLAG_PRESENT : 0) |
                            (yielded ? OxoOrder::FLAG_YIELDED : 0))
      end
      if timing
        # both clocks are read ONCE, here, and both endpoints of service and
        # service_cpu are the same two instants. The pre-work_cpu span started
        # before t_read and so was wider than the wall it was bucketed against.
        t_end = OxoTiming.now_ns
        c_end = OxoTiming.cpu_ns
        OxoTiming.record(
          ts0, t_read, t_built, t_end,
          GC.count - gc_c0, GC.stat(:major_gc_count) - gc_m0,
          (GC.respond_to?(:total_time) ? GC.total_time : 0) - gc_t0,
          c_end - cpu0,
          solo: solo, t_start: t_start, c_start: c_start, c_end: c_end,
          sched_start: sched_start
        )
      end
      registry&.idle(socket)
      # W1: a drain in progress means this response was the connection's last —
      # close instead of re-parking in the keepalive read (the drain fiber only closes
      # conns that were idle AT drain start; post-drain completions close themselves).
      break if registry&.draining?
    rescue StandardError => e
      if wrote_response
        # The response write itself failed (partial bytes may be on the wire): a
        # trailing error frame would corrupt the stream — bare close, logged.
        warn "oxo-async-worker: response write failed (#{e.class}: #{e.message}); closing bare"
        break
      end
      # App raise / encode failure with ZERO response bytes written: write the 500
      # error frame at a clean boundary, then CLOSE (pinned after-error outcome).
      warn "oxo-async-worker: request failed (#{e.class}: #{e.message}); writing 500 error frame"
      begin
        socket.write(OxoAsync.encode_error_frame)
        socket.flush
      rescue StandardError
        # Even the error frame failed — nothing more to do than close.
      end
      break
    end
  end
ensure
  registry&.unregister(socket)
  socket.close rescue nil
end

# `--filter <app.ru>`: load the app, read ONE 0xBF request frame from stdin, write ONE
# Full response frame to stdout, synchronously (no reactor, no socket, no async gem).
# Used to verify this worker's env matches the native S1 binary for the same frame bytes.
def run_filter(app_path)
  OxoAsync.load_app(app_path)
  raw = $stdin.binmode.read
  raise "short input" if raw.bytesize < FRAME_PREFIX_LEN
  raise "bad magic" unless raw.getbyte(0) == FRAME_MAGIC && raw.getbyte(1) == FRAME_VERSION
  remaining = raw.byteslice(2, 4).unpack1("V")
  envelope = raw.byteslice(FRAME_PREFIX_LEN, remaining)
  req = OxoAsync.decode_request_envelope(envelope)
  $stdout.binmode.write(OxoAsync.respond_to_request(req))
end

# OXO_WORKER_SCHED = unset | "nice:<0..19>" | "idle". The reactor sets its OWN
# scheduling class at boot, before any thread exists (Linux nice and policy are per
# thread; later threads inherit). "nice:N" raises this thread's nice (unprivileged,
# upward only); "idle" moves it to SCHED_IDLE through util-linux's chrt(1) on its own
# pid (unprivileged; no Fiddle, which is a bundled gem from Ruby 3.5 and absent from the
# app bundle), so a woken normal-class task (the edge) preempts it at once -- a
# DIAGNOSTIC dose for the 2-core handoff-wait question, never a default (an idle-class
# server starves under any co-tenant). Anything else refuses at boot. The contract line
# receipts the ACHIEVED policy and nice from /proc/self/stat (sched=<other|idle|...>:<nice>)
# so a cell whose call did not take is refused by the analyzer, never scored as treated.
module OxoSched
  SCHED_IDLE = 5
  POLICY_NAMES = { 0 => "other", 1 => "fifo", 2 => "rr", 3 => "batch", 5 => "idle", 6 => "deadline" }.freeze
  RAW = ENV["OXO_WORKER_SCHED"]
  WANT = begin
    case RAW
    when nil, "" then nil
    when "idle" then :idle
    when /\Anice:([0-9]|1[0-9])\z/ then Regexp.last_match(1).to_i
    else
      abort("oxo-async-worker: OXO_WORKER_SCHED=#{RAW.inspect} is not unset, nice:<0..19> or idle")
    end
  end

  class << self
    def apply!
      return if WANT.nil?

      if WANT == :idle
        ok = system("chrt", "-i", "-p", "0", Process.pid.to_s, out: File::NULL, err: File::NULL)
        abort("oxo-async-worker: chrt -i -p 0 #{Process.pid} failed (util-linux present?)") unless ok
        abort("oxo-async-worker: SCHED_IDLE did not take (policy #{policy.inspect})") unless policy == SCHED_IDLE
      else
        Process.setpriority(Process::PRIO_PROCESS, 0, WANT)
      end
    rescue SystemCallError => e
      abort("oxo-async-worker: OXO_WORKER_SCHED=#{RAW} failed: #{e.class}: #{e.message}")
    end

    # /proc/self/stat after the comm: state is field 3, nice field 19, policy field 41.
    def stat_fields
      File.read("/proc/self/stat").split(") ").last.split
    rescue SystemCallError, IOError
      nil
    end

    def policy
      f = stat_fields
      f && f[38].to_i
    end

    def receipt
      f = stat_fields
      return "?:#{Process.getpriority(Process::PRIO_PROCESS, 0)}" unless f

      "#{POLICY_NAMES.fetch(f[38].to_i, f[38])}:#{f[16].to_i}"
    end
  end
end

def main
  if ARGV[0] == "--filter"
    run_filter(ARGV[1] || "config.ru")
    return
  end

  socket_path = ARGV[0] or abort("usage: oxo_async_worker.rb <uds-socket-path> [app.ru]")
  app_path = ARGV[1] || ENV["OXO_WORKER_APP"] || "config.ru"
  OxoSched.apply! # first, before any thread exists (nice and policy are per thread)

  # (W1, panel MED-3) STDOUT DISCIPLINE: the supervisor scans stdout line-by-line
  # for the READY handshake with a 64 KB pre-READY cap — Rails/bootsnap/initializer
  # output on stdout would blow it, and an unflushed READY line would sit in the pipe
  # buffer past the readiness deadline. So: save the real stdout fd for the handshake,
  # point $stdout at stderr for everything else (operator contract: app logs go to
  # stderr or a file), and write READY with explicit flush.
  ready_io = $stdout.dup
  ready_io.sync = true
  $stdout.reopen($stderr)
  $stdout.sync = true

  # The flag must be set BEFORE the app loads: the Rails app pins :fiber isolation
  # under OXO_ASYNC=1 (config/application.rb), and the boot assertion above
  # verifies it took effect.
  ENV["OXO_ASYNC"] = "1"

  require "async"
  require "socket"

  OxoAsync.load_app(app_path)
  OxoTiming.arm! # no-op unless OXO_WORKER_TIMING_DIR is set (server mode only)
  OxoOrder.arm! # no-op unless OXO_WORKER_ORDER_DIR is set
  OxoOrder.check_mode! # timerpush is pinned to the receipted gem versions
  OxoOrder.install_counters!
  # receipt: the analyzer refuses a cell whose line disagrees with its spec or
  # whose async / io-event versions differ from those the unit test ran on.
  warn "oxo-async-worker: order=#{OxoOrder.armed? ? 'armed' : 'off'} " \
       "fair_read=#{OxoOrder.fair_mode} " \
       "async=#{defined?(Async::VERSION) ? Async::VERSION : '?'} " \
       "io_event=#{defined?(IO::Event::VERSION) ? IO::Event::VERSION : '?'} " \
       "validated=#{OxoOrder.validated? ? 1 : 0} " \
       "sched=#{OxoSched.receipt}"

  # W1: verify-only hygiene (the service owns dir creation); the old unconditional
  # steal-and-rebind + parent chmod was a downgrade vs the classic worker's refusals.
  prepare_socket_verified(socket_path)
  # The edge's --worker-socket gate REQUIRES 0600 (parent 0700) — same as the S1 worker
  # and the conn stub; without it the edge refuses to connect.
  server = UNIXServer.new(socket_path)
  File.chmod(0o600, socket_path)
  warn "oxo-async-worker: listening on #{socket_path} (0600), conn-per-request, fiber-per-connection"
  # realized-script census (the gate class): the A/B driver asserts the
  # RUNNING script's identity per cell — a stale or mis-pushed worker refuses the cell
  # instead of silently measuring the wrong code. Stderr, like all worker logging.
  begin
    require "digest"
    warn "oxo-async-worker: census script=#{File.expand_path(__FILE__)} " \
         "sha256=#{Digest::SHA256.file(__FILE__).hexdigest} pid=#{Process.pid}"
  rescue StandardError => e
    warn "oxo-async-worker: census unavailable (#{e.class}: #{e.message})"
  end

  # (W1, panel HIGH-2) SELF-PIPE DRAIN. Trap context may not block, may not take
  # locks, and must not touch the reactor: the handler's ONLY act is poking a pipe.
  # A dedicated reactor fiber owns the actual drain. Installing the traps here —
  # immediately BEFORE the READY line — keeps the default TERM disposition (immediate
  # clean death) for the whole app-boot window (panel MED-8): a supervisor drain that
  # lands mid-boot must not wait out a 120 s readiness budget or escalate to KILL.
  drain_r, drain_w = IO.pipe
  registry = ConnRegistry.new
  drain_deadline_ms = Integer(ENV["OXO_WORKER_DRAIN_DEADLINE_MS"] || "900")
  %w[TERM INT].each do |sig|
    Signal.trap(sig) do
      drain_w.write_nonblock("x")
    rescue IO::WaitWritable, IOError
      # Pipe already poked or closing — the drain is underway; nothing to do.
    end
  end

  ready_io.write("OXO_WORKER_READY=#{socket_path}\n")
  ready_io.flush

  Async do |task|
    # The drain fiber: parked on the self-pipe until a trap fires. Closes the listener
    # (the accept fiber rescues and exits WITHOUT stopping children — a task.stop'd
    # fiber unwinds via Async::Stop, which contract 2's StandardError rescue cannot
    # see, and a bare post-dispatch close is exactly the replay-ambiguous signature
    # the W0 edge contract exists to prevent), closes idles, then waits out the
    # bounded in-flight drain.
    task.async do |drain_task|
      drain_r.read(1)
      registry.start_drain!
      begin
        server.close
      rescue StandardError
        nil
      end
      registry.close_idle!
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + (drain_deadline_ms / 1000.0)
      while registry.in_flight_count.positive? &&
            Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline
        drain_task.sleep(0.01)
      end
      # the timing ledger's HEAVY payload lands HERE, at the end of the drain --
      # not only from at_exit. s1 proved why: every worker wrote 12 light dumps and
      # then died with full=false, because the supervisor's teardown ladder (TERM, then
      # the drain deadline plus a margin, then SIGKILL) does not reliably leave room for
      # an at_exit that has to serialize every bin array and a 6000-tuple reservoir. At
      # this point the listener is closed and the in-flight drain has finished, so no
      # request is being measured and the cost is outside the measured window; at_exit
      # still fires afterwards and simply rewrites the same file (tmp+rename, so a kill
      # mid-write leaves the earlier complete payload rather than a truncated one).
      OxoTiming.dump(full: true) if OxoTiming.armed?
      abandoned = registry.abandon_in_flight!
      if abandoned.positive?
        # One structured line (panel LOW-12): a clean drain must NOT print this; the
        # conformance suite asserts both directions. Truncation accounting stays at
        # the edge — the exit code is 0 either way (owner decision).
        warn %({"oxo_async_worker":"drain_deadline_expired","abandoned_in_flight":#{abandoned}})
      end
    end

    loop do
      client = begin
        server.accept
      rescue IOError, Errno::EBADF
        break # drain closed the listener; exit the accept fiber, children keep running
      end
      registry.register(client)
      # One FIBER per accepted connection: its keepalive loop serves one request at a
      # time; concurrency comes from MANY pooled connections, not interleaving on one.
      task.async { handle_conn(client, registry) }
    end
  end
  # The reactor returns once every fiber (drain + connections) has finished: exit 0.
end

main if $PROGRAM_NAME == __FILE__
