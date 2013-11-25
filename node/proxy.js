var jwt = require('jwt-simple');
var request = require('request');
var http = require('http');
var url = require('url');
var qs = require('qs');
var cookie = require('cookie');
var config = require('./config.json');

var server = http.createServer().listen(config.port);

http.globalAgent.maxSockets = 300;

function unknownError(res) {
  res.writeHead(301, {
    'Set-Cookie': 'proxy.auth=x; expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'Location': '/'
  });
  res.end();
}

function getAccessTokenFromAuthCode(auth_code, res, callback) {
  request({
    url: "https://github.com/login/oauth/access_token",
    method: "POST",
    form: {
      client_id: config.github.client_id,
      client_secret: config.github.client_secret,
      code: auth_code
    },
    headers: {
      'User-Agent': 'notes.pdx.esri.com'
    }
  }, function(error, response, body){
    if(!error && body) {
      var token_response = qs.parse(body);
      if(token_response && token_response.access_token) {
        callback(token_response.access_token);
      } else {
        unknownError(res);
      }
    } else {
      unknownError(res);
    }
  });
}

function getUsername(access_token, res, callback) {
  // Check the orgs the user is a member of
  request({
    url: "https://api.github.com/user",
    headers: {
      'Authorization': 'token '+access_token,
      'User-Agent': 'notes.pdx.esri.com'
    }
  }, function(error, response, body){
    if(!error && body) {
      try {
        var userInfo = JSON.parse(body);
        if(userInfo && userInfo.login) {
          callback(userInfo.login);
        } else {
          unknownError(res);
        }
      } catch(e) {
        unknownError(res);
      }
    } else {
      unknownError(res);
    }
  });
}

function getOrgsForUser(access_token, res, callback) {
  // Check the orgs the user is a member of
  request({
    url: "https://api.github.com/user/orgs",
    headers: {
      'Authorization': 'token '+access_token,
      'User-Agent': 'notes.pdx.esri.com'
    }
  }, function(error, response, body){
    if(!error && body) {
      try {
        var orgs = JSON.parse(body);
        callback(orgs);
      } catch(e) {
        unknownError(res);
      }
    } else {
      unknownError(res);
    }
  });
}

server.on('request', function (req, res) {
  var u = url.parse(req.url, true);

  if(u.pathname === "/_auth") {

    if(u.query && u.query.code) {
      // Auth callback from Github

      getAccessTokenFromAuthCode(u.query.code, res, function(access_token) {
        getOrgsForUser(access_token, res, function(orgs) {
          if(orgs && orgs.length) {

            var org_ids = orgs.map(function(o) { return o.login; });

            var authorized_org = false;
            console.log(config.orgs);

            config.orgs.forEach(function(o){
              console.log(o);
              if(org_ids.indexOf(o)) {
                authorized_org = o;
              }
            });

            if(authorized_org) {

              getUsername(access_token, res, function(username) {

                var session = {
                  authorized: true,
                  timestamp: new Date().getTime(),
                  org: authorized_org,
                  username: username
                };
                console.log("User signed in");
                console.log(session);
                var token = jwt.encode(session, config.session_secret);

                res.writeHead(301, {
                  'Set-Cookie': 'proxy.auth='+token,
                  'Location': '/'
                });
                res.end();

              });

            } else {
              unknownError(res);
            }

          } else {
            unknownError(res);
          }

        });
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
    // check for redirects
    if (config.redirect && Object.keys(config.redirect)) {
      var keys = Object.keys(config.redirect);
      for (var i = 0; i < keys.length; i++) {
        if (req.url.match(keys[i])) {
          res.writeHead(301, {
            'Location': config.redirect[keys[i]]
          });
          res.end();
          return;
        }
      }
    }

    var headers = req.headers;
    var authenticated = false;

    if(headers['cookie']) {
      var cookies = cookie.parse(headers['cookie']);

      var session = null;
      if(cookies['proxy.auth']) {
        session = jwt.decode(cookies['proxy.auth'], config.session_secret);
        if(session.username) {
          authenticated = true;
        }
      }
    }

    if(authenticated) {
      // Logged in, proxy the request to the backend
      var method = req.method;

      // Ignore the Host value of the proxy server and use the backend Host instead
      delete headers.host;

      // Include the username in the headers
      headers['X-Proxy-Username'] = session.username;
      headers['X-Proxy-Org'] = session.org;

      req.pipe(request({
        url: config.backend + req.url,
        headers: headers,
        method: method
      })).pipe(res);
    } else {
      // Not logged in, show the login link
      res.statusCode = 401;
      res.setHeader("Content-Type", "text/html");
      res.end('<a href="/_auth?start=true">Sign in with Github</a>');
    }
  }

});

console.log('proxy server running');
