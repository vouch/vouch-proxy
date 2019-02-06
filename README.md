# Vouch Proxy
# Renaming project to **Vouch Proxy** in January 2019

In January the project was renamed to [vouch/vouch-proxy](https://github.com/vouch/vouch-proxy) from `LassoProject/lasso`.  This is to [avoid a naming conflict](https://github.com/vouch/vouch-proxy/issues/35) with another project.

Other namespaces have been changed including the docker hub repo [lassoproject/lasso](https://hub.docker.com/r/lassoproject/lasso/) which has become [voucher/vouch-proxy](https://hub.docker.com/r/voucher/vouch-proxy)


## you should change your config to the new name as of `v0.4.0`

Existing configs for both nginx and Vouch Proxy (lasso) should work fine.  However it would be prudent to make these minor adjustments:

in `config/config.yml`

* change "lasso:" to "vouch:"

and in your nginx config

* change variable names "http_x_lasso_" to "http_x_vouch_"
* change the headers "X-Lasso-" to "X-Vouch-"

The examples below have been updated accordingly

Sorry for the inconvenience but we wanted to make this change at this relatively early stage of the project.

This notice will remain in the README through June 2019

# Vouch Proxy

an SSO solution for nginx using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module.

Vouch Proxy supports OAuth login via Google, [GitHub](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/), [IndieAuth](https://indieauth.spec.indieweb.org/), and OpenID Connect providers

If Vouch is running on the same host as the nginx reverse proxy the response time from the `/validate` endpoint to nginx should be less than 1ms

For support please file tickets here or visit our IRC channel [#vouch](irc://freenode.net/#vouch) on freenode

## Installation

* `cp ./config/config.yml_example ./config/config.yml`
* create OAuth credentials for Vouch Proxy at [google](https://console.developers.google.com/apis/credentials) or [github](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/)
  * be sure to direct the callback URL to the `/auth` endpoint
* configure nginx...

```{.nginxconf}
server {
    listen 443 ssl http2;
    server_name dev.yourdomain.com;
    root /var/www/html/;

    ssl_certificate /etc/letsencrypt/live/dev.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dev.yourdomain.com/privkey.pem;

    # send all requests to the `/validate` endpoint for authorization
    auth_request /validate;

    location = /validate {
      # Vouch Proxy can run behind the same nginx-revproxy
      # May need to add "internal", and comply to "upstream" server naming
      proxy_pass http://vouch.yourdomain.com:9090;

      # Vouch Proxy only acts on the request headers
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";

      # pass X-Vouch-User along with the request
      auth_request_set $auth_resp_x_vouch_user $upstream_http_x_vouch_user;

      # these return values are used by the @error401 call
      auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
      auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
      auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;
    }

    # if validate returns `401 not authorized` then forward the request to the error401block
    error_page 401 = @error401;

    location @error401 {
        # redirect to Vouch Proxy for login
        return 302 https://vouch.yourdomain.com:9090/login?url=$scheme://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err;
    }

    # proxy pass authorized requests to your service
    location / {
      proxy_pass http://dev.yourdomain.com:8080;
      #  may need to set
      #    auth_request_set $auth_resp_x_vouch_user $upstream_http_x_vouch_user
      #  in this bock as per https://github.com/vouch/vouch-proxy/issues/26#issuecomment-425215810
      # set user header (usually an email)
      proxy_set_header X-Vouch-User $auth_resp_x_vouch_user;
    }
}

```

If Vouch is configured behind the **same** nginx reverseproxy ([perhaps so you can configure ssl](https://github.com/vouch/vouch-proxy/issues/64#issuecomment-461085139)) be sure to pass the `Host` header properly, otherwise the JWT cookie cannot be set into the domain

```{.nginxconf}
server {
    listen 80 default_server;
    server_name vouch.yourdomain.com;
    location / {
       proxy_set_header Host vouch.yourdomain.com;
       proxy_pass http://127.0.0.1:9090;
    }
}

```

## Running from Docker

```bash
docker run -d \
    -p 9090:9090 \
    --name vouch-proxy \
    -v ${PWD}/config:/config \
    -v ${PWD}/data:/data \
    voucher/vouch-proxy
```

The [voucher/vouch-proxy](https://hub.docker.com/r/voucher/vouch-proxy/) Docker image is an automated build on Docker Hub

[![docker-build status](https://img.shields.io/docker/build/voucher/vouch-proxy.svg)](https://hub.docker.com/r/voucher/vouch-proxy/builds/)

If you are using [nginx-ingress](https://github.com/kubernetes/ingress-nginx) inside of kubernetes, you can configure your ingress with the following annotations (note quoting the auth-signin annotation):

```
    nginx.ingress.kubernetes.io/auth-signin: "https://vouch.yourdomain.com/login?url=$scheme://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err"
    nginx.ingress.kubernetes.io/auth-url: https://vouch.yourdomain.com
    nginx.ingress.kubernetes.io/auth-response-headers: X-Vouch-User
    nginx.ingress.kubernetes.io/auth-snippet: |
      # these return values are used by the @error401 call
      auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
      auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
      auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;
```

## Running from source

```bash
  go get ./...
  go build
  ./vouch-proxy
```

## /logout endpoint redirection

The Vouch Proxy `/logout` endpoint accepts a `url` parameter in the query string which can be used to `302` redirect a user to your orignal OAuth provider/IDP/OIDC provider's [revocation_endpoint](https://tools.ietf.org/html/rfc7009)

```
    https://vouch.oursites.com/login?url=https://oauth2.googleapis.com/revoke
```

logout resources..
 * [Google](https://developers.google.com/identity/protocols/OAuth2WebServer#tokenrevoke)
 * [Okta](https://developer.okta.com/docs/api/resources/oidc#logout)
 * [Auth0](https://auth0.com/docs/logout/guides/logout-idps)


## the flow of login and authentication using Google Oauth

* Bob visits `https://private.oursites.com`
* the nginx reverse proxy...
  * recieves the request for private.oursites.com from Bob
  * uses the `auth_request` module configured for the `/validate` path
  * `/validate` is configured to `proxy_pass` requests to the authentication service at `https://vouch.oursites.com/validate`
    * if `/validate` returns...
      * 200 OK then SUCCESS allow Bob through
      * 401 NotAuthorized then
        * respond to Bob with a 302 redirect to `https://vouch.oursites.com/login?url=https://private.oursites.com`

* vouch `https://vouch.oursites.com/validate`
  * recieves the request for private.oursites.com from Bob via nginx `proxy_pass`
  * it looks for a cookie named "oursitesSSO" that contains a JWT
  * if the cookie is found, and the JWT is valid
    * returns 200 to nginx, which will allow access (bob notices nothing)
  * if the cookie is NOT found, or the JWT is NOT valid
    * return 401 NotAuthorized to nginx (which forwards the request on to login)

* Bob is first forwarded briefly to `https://vouch.oursites.com/login?url=https://private.oursites.com`
  * clears out the cookie named "oursitesSSO" if it exists
  * generates a nonce and stores it in session variable $STATE
  * stores the url `https://private.oursites.com` from the query string in session variable $requestedURL
  * respond to Bob with a 302 redirect to Google's OAuth Login form, including the $STATE nonce

* Bob logs into his Google account using Oauth
  * after successful login
  * Google responds to Bob with a 302 redirect to `https://vouch.oursites.com/auth?state=$STATE`

* Bob is forwarded to `https://vouch.oursites.com/auth?state=$STATE`
  * if the $STATE nonce from the url matches the session variable "state"
  * make a "third leg" request of google (server to server) to exchange the OAuth code for Bob's user info including email address bob@oursites.com
  * if the email address matches the domain oursites.com (it does)
    * create a user in our database with key bob@oursites.com
    * issue bob a JWT in the form of a cookie named "oursitesSSO"
    * retrieve the session variable $requestedURL and 302 redirect bob back to $requestedURL

Note that outside of some innocuos redirection, Bob only ever sees `https://private.oursites.com` and the Google Login screen in his browser.  While Vouch does interact with Bob's browser several times, it is just to set cookies, and if the 302 redirects work properly Bob will log in quickly.

Once the JWT is set, Bob will be authorized for all other sites which are configured to use `https://vouch.oursites.com/validate` from the `auth_request` nginx module.

The next time Bob is forwarded to google for login, since he has already authorized the Vouch OAuth app, Google immediately forwards him back and sets the cookie and sends him on his merry way.  Bob may not even notice that he logged in via Vouch.


