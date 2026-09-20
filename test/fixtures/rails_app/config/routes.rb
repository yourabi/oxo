Rails.application.routes.draw do
  get "/fixture/large", to: "hello#large"
  get "/up" => "rails/health#show"
  get "/hello" => "hello#show", as: :hello
  get "/events" => "live#events"
  get "/cookies" => "hello#cookies_demo"
  get "/redirect-me" => "hello#redirect_me"
  get "/remote-ip" => "hello#remote_ip"
  get "/pressure/status" => "pressure#status"
  get "/pressure/db" => "pressure#db"
  get "/pressure/hold" => "pressure#hold"
  get "/pressure/redis" => "pressure#redis"
  get "/signed-cookie" => "hello#signed_cookie"
  get "/session-cookie" => "hello#session_cookie"
  get "/csrf-token" => "hello#csrf_token"
  post "/csrf-echo" => "hello#csrf_echo"
  post "/upload" => "hello#upload"
  get "/rails-boom" => "hello#boom"
end
