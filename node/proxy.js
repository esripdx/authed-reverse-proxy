var jwt = require('jwt-simple');
var request = require('request');
var http = require('http');
var url = require('url');
var qs = require('qs');
var cookie = require('cookie');
var config = require('./config.json');

var server = http.createServer().listen(9394);

function notFound(res) {
  res.statusCode = 404;
  res.end('404 Error');
}

function unknownError(res) {
  res.writeHead(301, {
    'Set-Cookie': 'proxy.auth=x; expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'Location': '/'
  });
  res.end();
}

server.on('request', function (req, res) {
  var u = url.parse(req.url, true);

  if(u.pathname === "/_auth") {

    if(u.query && u.query.code) {
      // Auth callback from Github

      // Get an access token from Github
      request({
        url: "https://github.com/login/oauth/access_token",
        method: "POST",
        form: {
          client_id: config.github.client_id,
          client_secret: config.github.client_secret,
          code: u.query.code
        }
      }, function(error, response, body){

        if(!error && body) {

          var token_response = qs.parse(body);

          if(token_response && token_response.access_token) {

            // Check the orgs the user is a member of
            request({
              url: "https://api.github.com/user/orgs",
              headers: {
                'Authorization': 'Bearer '+token_response.access_token
              }
            }, function(error, response, body){

              if(!error && body) {
                var orgs = JSON.parse(body);

                if(orgs && orgs.length) {

                  var org_ids = orgs.map(function(o) { return o.login });

                  var authorized_org = false;
                  console.log(config.orgs);

                  config.orgs.forEach(function(o){
                    console.log(o);
                    if(org_ids.indexOf(o)) {
                      authorized_org = o;
                    }
                  })

                  if(authorized_org) {

                    var session = {
                      authorized: true,
                      timestamp: new Date().getTime(),
                      org: authorized_org
                    }
                    console.log("User signed in");
                    console.log(session);
                    var token = jwt.encode(session, config.session_secret);

                    res.writeHead(301, {
                      'Set-Cookie': 'proxy.auth='+token,
                      'Location': '/'
                    });
                    res.end();

                  } else {
                    unknownError(res);
                  }

                } else {
                  unknownError(res);
                }

              } else {
                unknownError(res);
              }
            });

          } else {
            unknownError(res);
          }

        } else {
          unknownError(res);
        }

      });

    } else if(u.query && u.query.start) {
      res.writeHead(301, {
        'Location': 'https://github.com/login/oauth/authorize?client_id='+config.github.client_id
      });
      res.end();
    } else {
      res.writeHead(301, {
        'Set-Cookie': 'proxy.auth=x; expires=Thu, 01 Jan 1970 00:00:00 GMT',
        'Location': '/'
      });
      res.end();
    }

  } else {
    var headers = req.headers;

    var cookies = cookie.parse(headers['cookie']);
    var authenticated = false;

    if(cookies['proxy.auth']) {
      var token = jwt.decode(cookies['proxy.auth'], config.session_secret);
      console.log("0-0");
      console.log(token);
      authenticated = true;
    }

    if(authenticated) {
      // Logged in, proxy the request to the backend
      var method = req.method;

      delete headers.host;

      req.pipe(request({
        url: "http://indienews.dev" + req.url,
        headers: headers,
        method: method
      })).pipe(res);
    } else {
      // Not logged in, show the login link
      res.statusCode = 401;
      res.end('<a href="/_auth?start=true">Sign in with Github</a>');
    }
  }

});

console.log('proxy server running');
