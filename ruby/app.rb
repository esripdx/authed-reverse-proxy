
SiteConfig = YAML.load_file('config.yml')

class SinatraApp < Sinatra::Base

  @@hc = HTTPClient.new

  configure do
    set :sessions, true
    set :session_secret, 'foo'
  end

  use OmniAuth::Builder do
    provider :github, SiteConfig['github']['client_id'], SiteConfig['github']['client_secret']
  end

  def request_headers
    request.env.keys.select {|k,v| k.start_with? 'HTTP_'}.reduce({}) do |h,k|
      key = k.sub /^HTTP_/, ''
      key.downcase!
      key.gsub!(/(^|_)[a-z]/){|m| m.upcase}
      key.gsub! '_', '-'
      h[key] = request.env[k]
      h
    end
  end

  def unchunk hash = {}
    hash.select {|k,v| !(k == 'Transfer-Encoding' && v == 'chunked') }
  end

  def proxy method, path, _params = params, headers = request_headers
    ps = _params.empty? ? nil : _params
    r = @@hc.__send__ method, path, ps, request_headers
    status r.status
    headers unchunk(r.headers)
    r.body
  end

  get /^(?!\/auth)/ do
    if false && !session[:username]
      <<-HTML
      <p><a href='/auth/github'>Sign in with Github</a></p>
      HTML
    else
      # Proxy to backend
      proxy :get, SiteConfig['backend'] + request.path
    end
  end

  post /^(?!\/auth)/ do
    if !session[:username]
      <<-HTML
      <p><a href='/auth/github'>Sign in with Github</a></p>
      HTML
    else
      # Proxy to backend
      proxy :post, SiteConfig['backend'] + request.path + '?' + request.query_string
    end
  end

  get '/logout' do
    session[:username] = nil
    redirect '/'
  end

  get '/auth/:provider/callback' do

    # Check if the user is a member of the required organization
    orgs = JSON.parse(@@hc.get("https://api.github.com/user/orgs", nil, {
      'Authorization' => "Bearer #{request.env['omniauth.auth']['credentials']['token']}"
    }).body)

    authorized = false

    if orgs 
      org_ids = orgs.map{|o| o['login']}
      if (org_ids & SiteConfig['github_orgs']).length > 0
        authorized = true
      end
    end

    if authorized
      session[:username] = request.env['omniauth.auth']['extra']['raw_info']['login']
      redirect '/'
      # erb "<h1>#{params[:provider]}</h1>
      #      <pre>#{JSON.pretty_generate(orgs)}</pre>
      #      <pre>#{JSON.pretty_generate(request.env['omniauth.auth'])}</pre>
      #      "
    else
      erb "<h1>Not Authorized</h1>"
    end
  end

end
