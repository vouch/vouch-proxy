# Lasso

an SSO solution for an nginx reverse proxy using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module

If lasso is running on the same host as the nginx reverse proxy the response time from the `/validate` endpoint to nginx should be less than 1ms

## the flow of first time login

* Bob visits `https://private.oursites.com`
* the nginx reverse proxy...
  * recieves the request for private.oursites.com from Bob
  * uses the `auth_request` module configured for the `/validate` path
  * `/validate` is configured to `proxy_pass` requests to the authentication service at `https://login.oursites.com/validate`
    * if `/validate` returns...
      * 200 OK then SUCCESS allow Bob through
      * 401 NotAuthorized then
        * respond to Bob with a 302 redirect to `https://login.oursites.com/login?url=https://private.oursites.com`

* nginx contacts `https://login.oursites.com/validate`
  * recieves the request for private.oursites.com from Bob via nginx `proxy_pass`
  * it looks for a cookie named "oursitesSSO" that contains a JWT
  * if the cookie is found, and the JWT is valid
    * returns 200 to nginx, which will allow access (bob notices nothing)
  * if the cookie is NOT found, or the JWT is NOT valid
      * return 401 NotAuthorized to nginx (which forwards the request on to login)

* Bob is first forwarded briefly to `https://login.oursites.com/login?url=https://private.oursites.com`
  * clears out the cookie named "oursitesSSO" if it exists
  * generates a nonce and stores it in session variable "state"
  * stores the url `https://private.oursites.com` from the query string in session variable "requestedURL"
  * respond to Bob with a 302 redirect to Google's OAuth Login form, including the "state" nonce

* Bob logs into his Google account using Oauth
  * after successful login
  * Google responds to Bob with a 302 redirect to `https://login.oursites.com/auth?state=$STATE`

* Bob is forwarded to `https://login.oursites.com/auth?state=$STATE`
  * if the "state" nonce from the url matches the session variable "state"
  * make a request of google (server to server) to exchange the OAuth code for Bob's user info including email address bob@oursites.com
  * if the email address matches the domain oursites.com (it does)
    * create a user in our database with key bob@oursites.com
    * issue bob a JWT in the form of a cookie named "oursitesSSO"
    * retrieve the session variable "requestedURL" and 302 redirect bob back to `https://private.oursites.com`

Note that outside of some innocuos redirection, Bob only ever sees `https://private.oursites.com` and the Google Login screen in his browser.  While Lasso does interact with Bob's browser several times, it is just to set cookies, and if the 302 redirects work properly Bob will log in quickly.

Once the JWT is set, Bob's will be authorized for all other sites which are configured to use `https://login.oursites.com/validate` from the `auth_request` nginx module.

The next time Bob is forwarded to google for login, since he has already authorized the site it immediately forwards him back and sets the cookie and sends him on his merry way.  Bob may not even notice that he logged in via lasso.

## Installation

example nginx config...

```{.nginxconf}
server {
    listen 80 default_server;
    server_name dev.bnf.net;

    root /var/www/html/;
    auth_request /validate;
    error_page 401 = @error401;

    location @error401 {
        return 302 https://login.bnf.net:9090/login?url=$scheme://$http_host$request_uri&lasso-failcount=$auth_resp_failcount&X-Lasso-Token=$auth_resp_jwt&error=$auth_resp_err;
    }

    location = /validate {
       internal;

       proxy_pass https://login.bnf.net:9090;
       proxy_pass_request_body     off;

       proxy_set_header Content-Length "";
       proxy_set_header Host $http_host;
       proxy_set_header X-Real-IP $remote_addr;
       proxy_set_header Cookie $http_cookie;
       proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
       proxy_set_header X-Forwarded-Proto $scheme;

       # these return values are fed to the @error401 call
       auth_request_set $auth_resp_jwt $upstream_http_x_lasso_jwt;
       auth_request_set $auth_resp_err $upstream_http_x_lasso_err;
       auth_request_set $auth_resp_failcount $upstream_http_x_lasso_failcount;
    }
}

```

## Docker