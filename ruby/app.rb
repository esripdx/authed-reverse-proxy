
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
    env.select {|k,v| k.start_with? 'HTTP_'}
      .collect {|pair| [pair[0].sub(/^HTTP_/, ''), pair[1]]}
      .collect {|pair| pair.join(": ") << "\n"}
      .sort
  end

  get /^(?!\/auth)/ do
    if false && !session[:username]
      <<-HTML
      <p><a href='/auth/github'>Sign in with Github</a></p>
      HTML
    else
      # Proxy to backend
      puts request_headers
      path = SiteConfig['backend'] + request.path
      puts path
      puts params.inspect

      r = @@hc.get path, (params.empty? ? nil : params), request_headers
      status r.status
      headers r.headers
      puts r.headers.inspect
      r.body
    end
  end

  post /^(?!\/auth)/ do
    if !session[:username]
      <<-HTML
      <p><a href='/auth/github'>Sign in with Github</a></p>
      HTML
    else
      # Proxy to backend
      r = @@hc.post SiteConfig['backend'] + request.path, request.querystring
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
