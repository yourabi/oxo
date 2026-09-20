# frozen_string_literal: true
#
# Fiber-per-connection Rack worker using the binary frame protocol.
# The Ruby async reactor serves Rack/Rails over a private 0600 Unix socket.
# Each accepted connection has one fiber and one request in flight. The edge
# can reuse idle connections. Scheduler-aware I/O yields to other fibers;
# requests on separate sockets have independent response framing.
# Worker protocol invariants:
# 1. Invoke the app only after reading and decoding a complete frame. A malformed
# or truncated request closes with no app call and no response bytes.
# 2. After dispatch, write either the app response or an error frame. If response
# bytes may already have been written, close instead of appending another
# frame. Close after an error response. Abrupt process death can bypass this
# handling, so the edge must not retry a delivered async request after EOF.
# 3. In steady state, only the edge retires idle pooled connections. The worker
# waits without an idle timeout; shutdown separately closes idle sockets.
# Rack environment construction must match the native worker for identical
# request frames. The shared rules are in oxo-worker/src/linux/ruby.rs and
# frame.rs: preserve Host, strip Connection and forwarding-identity headers,
# strip reserved x-oxo-* metadata, and reject underscore-bearing header names.
# The environment parity tests run both worker implementations on the same bytes.

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

# The service sets this for multiple worker processes. Match the native worker's
# boolean parsing: accept 1/true/yes and 0/false/no; reject unknown values so
# rack.multiprocess cannot silently misreport the process model.
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

  # Rack environment construction corresponding to the native worker.

  # Bounded, pre-seeded frozen key table for the per-header CGI key build. Names
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

  # Filter decoded frame headers before build_env: lowercase defensively, keep
  # Host, and remove Connection, forwarding identity, reserved metadata and names
  # containing underscores, which would alias dashed names after CGI conversion.
  # Filter and flatten headers into the [key, value,...] array build_env consumes,
  # preserving input order without intermediate arrays for each header.
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

  # Build the native worker's Rack environment from filtered, flat headers.
  # server_port is a string. Empty requests share a frozen binary backing string,
  # but each receives its own StringIO with independent cursor state. Avoid changing
  # the encoding of that frozen string.
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
  # Emit response header pairs directly, preserving expansion rules and order.
  def flatten_header_pairs(headers)
    pairs = []
    headers.each do |k, v|
      key = k.to_s
      # fast path: a plain String value with no embedded LF (the overwhelmingly
      # common case) needs no Array wrap, no split, no per-segment loop. Expansion
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

  # Match native-worker response hygiene: framing belongs to the server; drop
  # header names and values containing control bytes to prevent response splitting.
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
  # Build directly into one frame buffer and fill its length field at the end.
  # The caller may reuse a buffer owned by the connection fiber. Error and drain
  # frames use fresh buffers because drain writes can overlap an app fiber paused
  # on socket backpressure; sharing that buffer would corrupt the wire bytes.
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
    # Rails executor wrapper: reload guards, connection release and request-state reset.
    @executor = defined?(Rails) && Rails.respond_to?(:application) && Rails.application ? Rails.application.executor : nil
    # Require fiber isolation when ActiveSupport is present. Thread isolation would
    # share request state across fibers on one reactor thread. Read the setting from
    # ActiveSupport::IsolatedExecutionState, the owner of the isolation API.
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
      MULTIPROCESS, # rack.multiprocess: true for multiple worker processes
      flat, req[:body]
    )
    status, headers, body = call_app(env)
    body_bytes = collect_body(body)
    resp_headers = sanitize_response_headers(flatten_header_pairs(headers))
    encode_full_response(Integer(status), resp_headers, body_bytes, out_buf)
  end

  # Collect the Rack response body into binary bytes and close it when supported.
  # This worker buffers the entire body and emits one Full frame per response.
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

# Connection drain registry and socket permission checks.

# Track each connection's phase during bounded drain:
#:idle closes immediately when drain starts.
#:in_app has no response bytes yet; drain expiry attempts an error frame.
#:writing may have sent bytes; drain expiry closes without appending a frame.
# The supervisor signals the edge first. One reactor thread owns the registry,
# so state transitions require no mutex, but socket I/O can yield to another fiber.
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
  # frame (except:writing — see above), then close. Returns the abandoned count.
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

# The service creates the runtime directory; the worker verifies it. The parent
# must exist and have no group/other access. Reject unsafe permissions instead of
# changing them. Unlink a stale socket only when it is a socket owned by this user.
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

# ---- optional worker timing collection (env-gated; OFF costs one nil check) ----------
#
# Optional timing collection enabled by OXO_WORKER_TIMING_DIR:
# sched: edge CLOCK_MONOTONIC frame stamp through worker decode completion,
# including transport, scheduling and decode time.
# work: decode completion through response frame construction.
# write: frame construction through socket flush.
# GC counters bracket each request; work histograms separate GC and non-GC spans.
# A native dump thread writes timing-<pid>.json atomically every five seconds;
# full histograms and tail samples are written during drain and exit.
module OxoTiming
  BUCKETS = 26 # floor(log2 ns), mirroring the edge's hop-timing shape
  # Tail threshold and bounded reservoir capacity per reactor. The threshold is
  # configurable; the default is 2^23 ns, approximately 8.39 ms. Overflow and
  # replacement counters describe which samples the bounded reservoir retains.
  TAIL_NS = Integer(ENV.fetch("OXO_WORKER_TAIL_NS", (1 << 23).to_s))
  TAIL_RESERVOIR_CAP = 6000

  # Linear bins match the edge's 64-microsecond histogram spacing up to 32.768 ms.
  # The saturated top bin has a separate count and sum. Retain exact sample totals
  # alongside both linear and log2 bins so consumers can detect saturation.
  LIN_BINS = 512
  LIN_BIN_US = 64
  LIN_BIN_NS = LIN_BIN_US * 1_000
  # service prefix read returned -> socket flushed: the worker's whole service
  # time at the vantage the edge's exchange span meets (the headline).
  # service_cpu this thread's CPU over the SAME two endpoints. Under fibers a
  # sibling's CPU accrues on this thread while this request is suspended,
  # so service - service_cpu is a LOWER BOUND on the time the thread was
  # not running this request, not a measurement of "waiting".
  # read_decode prefix returned -> decode done; work_nogc/work_gc decode -> frame
  # built, split by whether a collection landed in the span;
  # write frame built -> flushed.
  LINEAR_BLOCKS = %w[service service_cpu read_decode work_nogc work_gc write].freeze

  # the CONSECUTIVE-request ring.
  #
  # Preserve request adjacency with a ring of sequential samples. Tail sampling
  # alone cannot measure covariance between neighboring requests. Preallocated
  # integer arrays avoid per-request objects; incremental binary appends avoid
  # serializing the whole ring during periodic dumps.
  # Each record is three little-endian u32 values: service nanoseconds, wall minus
  # thread-CPU nanoseconds over that span, and metadata (GC events in the low byte,
  # flags above). Values beyond the approximately 4.29-second range saturate and
  # increment an overflow counter instead of wrapping. Each record is 12 bytes.
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
      # Bounded joint tail samples retain a monotonic timestamp and related metrics:
      # t=read stamp, s=scheduling span, w=work wall time, c=thread CPU over the span,
      # g=GC events, gn=GC time, wr=write time. Thread CPU can include other fibers'
      # work while this request yields, so it is an upper bound on this request's CPU.
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
      # Sample voluntary and involuntary context switches from /proc/self/status
      # at each dump. These process-status counters have a different scope from
      # request-bracketed timings; compare deltas over matching time windows.
      @switch0 = read_switches
      @switches = @switch0
      # Record the previous dump's CPU and elapsed-time costs separately.
      # CPU covers execution by the dumper thread, including serialization while it
      # holds the GVL. Wall time also includes I/O and time waiting to run; it must
      # not be interpreted as the duration that the reactor was blocked by the dumper.
      @dump_hold_ns = nil
      @dump_cpu_ns = nil
      # A cumulative counter series permits deltas between timestamped dump boundaries.
      @series = []
      @counters = { "requests" => 0, "no_stamp" => 0, "gc_events" => 0,
                    "major_gc_events" => 0, "gc_time_ns" => 0, "dump_failures" => 0,
                    "tail_samples_dropped" => 0,
                    # Use the dump thread's CPU cost for execution overhead. Wall time also
                    # includes scheduling delay and I/O, so it cannot identify GVL hold time.
                    "service_recorded" => 0, "dumps" => 0,
                    # Keep periodic and full-dump maxima separate. Periodic dumps overlap
                    # request serving; the full payload is written after the bounded drain.
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

    # Write a sequential ring sample into preallocated integer arrays without per-request objects.
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

    # Append only new ring records in binary form, avoiding repeated full-ring serialization.
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
      # Sample when scheduling, work or full service time crosses the configured
      # tail threshold. Including service captures delays in reads and writes even
      # when app execution itself remains below the threshold.
      sched_ns = ts0 ? t_read - ts0 : nil
      unless (t_built - t_read) >= TAIL_NS || (sched_ns && sched_ns >= TAIL_NS) ||
             (service && service >= TAIL_NS)
        return
      end

      # UNIFORM reservoir sampling (algorithm R). First-N-then-drop clusters the
      # sample in whichever phase produced tail events earliest, which makes any
      # cross-arm or cross-phase comparison invalid without saying so.
      @tail_seen += 1
      # sv is service wall time; sc is thread CPU over the same endpoints.
      # Their difference can understate this request's off-CPU time when another
      # fiber runs on the same thread. t is the monotonic timestamp.
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

    # Write full-dump cost separately because a payload cannot include its own
    # completed serialization and write time. Missing this sidecar does not imply
    # the timing payload itself is incomplete.
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
    # Keep periodic payloads small. JSON serialization runs with the GVL and can
    # delay the reactor; write the full histograms and reservoir after drain instead.
    def dump(full: false)
      return unless @dir

      hold0 = now_ns
      cpu0 = cpu_ns
      path = File.join(@dir, "timing-#{Process.pid}.json")
      tmp = "#{path}.tmp"
      require "json"
      # Record cumulative counters and tail exceedances for timestamped interval deltas.
      @sched_stat = read_schedstat || @sched_stat
      @switches = read_switches || @switches
      @series << {
        "t" => now_ns,
        "req" => @counters["requests"],
        # Sample cumulative reactor run-queue delay for interval comparisons.
        "run_delay_ns" => (@sched_stat && @sched_stat[1]),
        "run_time_ns" => (@sched_stat && @sched_stat[0]),
        "gc_ev" => @counters["gc_events"],
        "gc_ns" => @counters["gc_time_ns"],
        # Report all schedstat fields, including the number of scheduling slices.
        "slices" => (@sched_stat && @sched_stat[2]),
        "vol" => (@switches && @switches[0]),
        "nonvol" => (@switches && @switches[1]),
        "ring_n" => @ring_n, "ring_lost" => @ring_lost, "ring_sat" => @ring_sat,
        "samp_n" => @samp_idx.length,
        "sched_hi" => @sched[23..].sum,
        "work_hi" => @work_nogc[24..].sum + @work_gc[24..].sum,
        # This point contains the preceding dump's cost because the current write
        # has not finished. The first point has no prior cost. CPU and wall spans
        # have different meanings and must not be substituted for each other.
        "prev_hold_ns" => @dump_hold_ns,
        "prev_cpu_ns" => @dump_cpu_ns
      }
      @series.shift if @series.length > 400
      payload = {
        "pid" => Process.pid,
        "buckets" => BUCKETS,
        "full" => full,
        # Report the effective tail threshold so consumers do not mix different populations.
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
        # The full dump includes all histograms and the reservoir. Keep its cost
        # separate from periodic dumps because it runs after the bounded drain.
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

# Optional request-order recording and pre-read scheduling.
#
# OXO_WORKER_ORDER_DIR=<dir> arms a per-request ring: {conn fileno, start ns,
# end ns, flags} in four preallocated Integer arrays (no per-request object). The
# prefix is first tried with read_nonblock, so "present" = the frame was already
# there when the fiber looked. flags: bit 0 present, bit 1 yielded (the fair-read
# path passed the scheduler before this read). Dumps are incremental and binary:
# every 10 s the entries since the last dump are appended to order-<pid>.bin as
# little-endian u64 quads, and a small JSON sidecar records per-dump counts and the
# reactor thread's run-queue delay. Never JSON of the ring.
#
# OXO_WORKER_FAIR_READ selects the scheduling step before each frame read:
# yield2 (default, including unset/empty): yield twice to the scheduler.
# off or 0: read without a scheduling step.
# pair or 1: sleep(0), then yield.
# timerpush: register a zero timer to push this fiber, then transfer.
# sleep0 or yield1: use only the named primitive. Unknown values fail at boot.
#
# For io-event 1.19 / async 2.42, ready_flush captures the ready list's tail.
# A second yield during that flush places this fiber beyond the captured tail;
# the selector can serve ready sockets before the following flush resumes it.
# For pair, the zero timer first transfers to the loop, then yields this fiber
# onto the ready list. Merely waiting for readability does not establish that
# ordering when a busy socket remains readable. The scheduling step follows
# idle/drain bookkeeping; a drain during it is handled by the next read.
module OxoOrder
  CAP = 65_536
  FLAG_PRESENT = 1
  FLAG_YIELDED = 2
  FAIR_MODES = %w[off pair yield2 timerpush sleep0 yield1].freeze
  DEFAULT_FAIR_MODE = "yield2" # default pre-read scheduling mode
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

    # timerpush uses a private scheduler API and requires the checked gem versions.
    # For other versions, yield2 remains available but its ordering is unverified;
    # log a warning and validated=0 rather than claiming the same ordering.
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

    # Print the integer scheduling counters at exit, independently of the optional ring.
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
      # Pair wall and monotonic timestamps for correlating external observations.
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
  # before the next iteration reuses it; drain/error frames never touch it).
  # The ENVELOPE stays a fresh string by design: decoded header/body slices alias it
  # via byteslice (CoW), and refilling an aliased buffer forces an unshare-copy that
  # refunds the reuse.
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
        # any, completes through the ordinary read.
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
      # timing collection must not change frame-read behavior.
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
    registry&.busy(socket) # drain-visible: abandoned :in_app connections receive a 500 frame
    # is this request ALONE on this worker? busy has already counted it,
    # so a count of 1 means nothing else is in flight here. Recorded only when
    # timing is armed, and it is a plain count over a small hash on a path that
    # already walks it for drain visibility.
    solo = timing ? (registry.nil? || registry.in_flight_count == 1) : nil
    wrote_response = false
    begin
      frame = OxoAsync.respond_to_request(req, out_buf)
      t_built = OxoTiming.now_ns if timing
      wrote_response = true # the write below either sends the whole frame or raises
      registry&.writing(socket) # after this point, drain closes without appending an error frame
      socket.write(frame)
      socket.flush
      if order
        OxoOrder.record(socket.fileno, t_start, OxoOrder.now_ns,
                            (present ? OxoOrder::FLAG_PRESENT : 0) |
                            (yielded ? OxoOrder::FLAG_YIELDED : 0))
      end
      if timing
        # Bracket full service wall time and thread CPU at the same two endpoints
        # so their difference is not distorted by mismatched measurement spans.
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
      # a drain in progress means this response was the connection's last —
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
# Used to verify this worker's env matches the native worker binary for the same frame bytes.
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

# OXO_WORKER_SCHED accepts unset, nice:<0..19>, or idle. Set the reactor's
# Linux scheduling policy before starting other threads, which inherit it.
# nice:N lowers scheduling priority; idle uses util-linux chrt on this process.
# This diagnostic setting is disabled by default. SCHED_IDLE can starve under
# competing work. Log the achieved policy and nice value from /proc/self/stat;
# reject unsupported values at boot.
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

  # STDOUT DISCIPLINE: the supervisor scans stdout line-by-line
  # for the READY handshake with a 64 KB pre-READY cap — Rails/bootsnap/initializer
  # output on stdout would blow it, and an unflushed READY line would sit in the pipe
  # buffer past the readiness deadline. So: save the real stdout fd for the handshake,
  # point $stdout at stderr for everything else (operator contract: app logs go to
  # stderr or a file), and write READY with explicit flush.
  ready_io = $stdout.dup
  ready_io.sync = true
  $stdout.reopen($stderr)
  $stdout.sync = true

  # The flag must be set BEFORE the app loads: the Rails app pins:fiber isolation
  # under OXO_ASYNC=1 (config/application.rb), and the boot assertion above
  # verifies it took effect.
  ENV["OXO_ASYNC"] = "1"

  require "async"
  require "socket"

  OxoAsync.load_app(app_path)
  OxoTiming.arm! # no-op unless OXO_WORKER_TIMING_DIR is set (server mode only)
  OxoOrder.arm! # no-op unless OXO_WORKER_ORDER_DIR is set
  OxoOrder.check_mode! # timerpush requires the checked gem versions
  OxoOrder.install_counters!
  # Log the effective fair-read mode and scheduler dependency versions.
  warn "oxo-async-worker: order=#{OxoOrder.armed? ? 'armed' : 'off'} " \
       "fair_read=#{OxoOrder.fair_mode} " \
       "async=#{defined?(Async::VERSION) ? Async::VERSION : '?'} " \
       "io_event=#{defined?(IO::Event::VERSION) ? IO::Event::VERSION : '?'} " \
       "validated=#{OxoOrder.validated? ? 1 : 0} " \
       "sched=#{OxoSched.receipt}"

  # Verify socket-directory ownership and permissions; creation belongs to the service.
  prepare_socket_verified(socket_path)
  # The edge's --worker-socket gate REQUIRES 0600 (parent 0700) — same as the native worker worker
  # and the conn stub; without it the edge refuses to connect.
  server = UNIXServer.new(socket_path)
  File.chmod(0o600, socket_path)
  warn "oxo-async-worker: listening on #{socket_path} (0600), conn-per-request, fiber-per-connection"
  # Log the running script digest on stderr so its source identity is inspectable.
  begin
    require "digest"
    warn "oxo-async-worker: census script=#{File.expand_path(__FILE__)} " \
         "sha256=#{Digest::SHA256.file(__FILE__).hexdigest} pid=#{Process.pid}"
  rescue StandardError => e
    warn "oxo-async-worker: census unavailable (#{e.class}: #{e.message})"
  end

  # SELF-PIPE DRAIN. Trap context may not block, may not take
  # locks, and must not touch the reactor: the handler's ONLY act is poking a pipe.
  # A dedicated reactor fiber owns the actual drain. Installing the traps here —
  # immediately BEFORE the READY line — keeps the default TERM disposition (immediate
  # clean death) for the whole app-boot window: a supervisor drain that
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
    # The drain fiber closes the listener and idle connections, then waits for
    # in-flight work up to the deadline. Do not stop app fibers on listener close:
    # Async::Stop bypasses StandardError handling and could interrupt response
    # framing after dispatch.
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
      # Write full timing output after draining rather than relying only on at_exit:
      # the supervisor can escalate to SIGKILL after its grace period. Atomic rename
      # preserves a complete earlier payload if a later exit-time write is interrupted.
      OxoTiming.dump(full: true) if OxoTiming.armed?
      abandoned = registry.abandon_in_flight!
      if abandoned.positive?
        # Log one structured abandonment line only when drain expires with work left.
        # The edge accounts for truncated responses; this worker exits zero either way.
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
