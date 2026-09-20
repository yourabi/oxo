# frozen_string_literal: true

# Rails request/response fixture for the Pingora edge and native/async workers.
class HelloController < ApplicationController
  skip_forgery_protection except: :csrf_echo

  def show
    render json: {
      message: "Hello from Oxo + Rails",
      method: request.request_method,
      path: request.path,
      query: request.query_string,
      scheme: request.scheme,
      ssl: request.ssl?,
      host: request.host,
      host_with_port: request.host_with_port,
      server: "#{request.server_name}:#{request.server_port}",
      protocol: request.protocol,
      base_url: request.base_url
    }
  end

  # Verifies repeated Set-Cookie headers survive the edge/worker round trip.
  def cookies_demo
    response.set_cookie("oxo_a", value: "1", path: "/")
    response.set_cookie("oxo_b", value: "2", path: "/")
    render json: { cookies: 2 }
  end

  def redirect_me
    redirect_to hello_url(from: "redirect")
  end

  def remote_ip
    render json: {
      remote_addr: request.env["REMOTE_ADDR"],
      remote_ip: request.remote_ip,
      x_forwarded_for: request.env.key?("HTTP_X_FORWARDED_FOR"),
      forwarded: request.env.key?("HTTP_FORWARDED")
    }
  end

  def signed_cookie
    seen = cookies.signed[:oxo_seen].to_i + 1
    cookies.signed[:oxo_seen] = { value: seen.to_s, path: "/", httponly: true }
    render json: { seen: seen }
  end

  def session_cookie
    session[:oxo_session_seen] = session[:oxo_session_seen].to_i + 1
    render json: { session_seen: session[:oxo_session_seen] }
  end

  def csrf_token
    render json: { csrf: form_authenticity_token }
  end

  def csrf_echo
    render json: { echoed: request.raw_post }
  end

  def upload
    file = params.require(:file)
    bytes = file.read
    render json: { filename: file.original_filename, size: bytes.bytesize, hex: bytes.unpack1("H*") }
  end

  def large
    render plain: "a" * 262_144
  end

  def boom
    raise "oxo rails boom"
  end

end
