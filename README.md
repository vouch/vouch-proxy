# Vouch Proxy

an SSO solution for Nginx using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module.

Vouch Proxy supports many OAuth login providers and can enforce authentication to...

* Google
* [GitHub](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/)
* GitHub Enterprise
* [IndieAuth](https://indieauth.spec.indieweb.org/)
* [Okta](https://developer.okta.com/blog/2018/08/28/nginx-auth-request)
* [ADFS](https://github.com/vouch/vouch-proxy/pull/68)
* [AWS Cognito](https://github.com/vouch/vouch-proxy/issues/105)
* Keycloak
* [OAuth2 Server Library for PHP](https://github.com/vouch/vouch-proxy/issues/99)
* most other OpenID Connect (OIDC) providers

Please do let us know when you have deployed Vouch Proxy with your preffered IdP or library so we can update the list.

If Vouch is running on the same host as the Nginx reverse proxy the response time from the `/validate` endpoint to Nginx should be less than 1ms

## Installation

* `cp ./config/config.yml_example ./config/config.yml`
* create OAuth credentials for Vouch Proxy at [google](https://console.developers.google.com/apis/credentials) or [github](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/)
  * be sure to direct the callback URL to the `/auth` endpoint
* configure Nginx...

The following nginx config assumes..

* nginx, vouch.yourdomain.com and dev.yourdomain.com are running on the same server
* you are running both domains behind https and have valid certs for both (if not, change to `listen 80`)

```{.nginxconf}
server {
    listen 443 ssl http2;
    server_name protectedapp.yourdomain.com;
    root /var/www/html/;

    ssl_certificate /etc/letsencrypt/live/dev.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dev.yourdomain.com/privkey.pem;

    # send all requests to the `/validate` endpoint for authorization
    auth_request /validate;

    location = /validate {
      # forward the /validate request to Vouch Proxy
      proxy_pass http://127.0.0.1:9090/validate;
      # be sure to pass the original host header
      proxy_set_header Host $http_host;

      # Vouch Proxy only acts on the request headers
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";

      # optionally add X-Vouch-User as returned by Vouch Proxy along with the request
      auth_request_set $auth_resp_x_vouch_user $upstream_http_x_vouch_user;
      # optinally add X-Vouch-IdP-AccessToken or IdToken 
      auth_request_set $auth_resp_x_vouch_idp_accesstoken $upstream_http_x_vouch_idp_accesstoken;
      auth_request_set $auth_resp_x_vouch_idp_idtoken $upstream_http_x_vouch_idp_idtoken;

      # these return values are used by the @error401 call
      auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
      auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
      auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;

      # Vouch Proxy can run behind the same Nginx reverse proxy
      # may need to comply to "upstream" server naming
      # proxy_pass http://vouch.yourdomain.com/validate;
      # proxy_set_header Host $http_host;
    }

    # if validate returns `401 not authorized` then forward the request to the error401block
    error_page 401 = @error401;

    location @error401 {
        # redirect to Vouch Proxy for login
        return 302 https://vouch.yourdomain.com/login?url=$scheme://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err;
        # you usually *want* to redirect to Vouch running behind the same Nginx config proteced by https  
        # but to get started you can just forward the end user to the port that vouch is running on
        # return 302 http://vouch.yourdomain.com:9090/login?url=$scheme://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err;
    }

    location / {
      # forward authorized requests to your service protectedapp.yourdomain.com
      proxy_pass http://127.0.0.1:8080;
      # you may need to set
      #    auth_request_set $auth_resp_x_vouch_user $upstream_http_x_vouch_user
      #    auth_request_set $auth_resp_x_vouch_idp_accesstoken $upstream_http_x_vouch_idp_accesstoken;
      #    auth_request_set $auth_resp_x_vouch_idp_idtoken $upstream_http_x_vouch_idp_idtoken;
      #  in this bock as per https://github.com/vouch/vouch-proxy/issues/26#issuecomment-425215810
      # set user header (usually an email)
      proxy_set_header X-Vouch-User $auth_resp_x_vouch_user;
      # optionally pass the accesstoken or idtoken 
      proxy_set_header X-Vouch-IdP-AccessToken $auth_resp_x_vouch_idp_accesstoken;
      proxy_set_header X-Vouch-IdP-IdToken $auth_resp_x_vouch_idp_idtoken;
    }
}

```

If Vouch is configured behind the **same** Nginx reverse proxy (perhaps so you can configure ssl) be sure to pass the `Host` header properly, otherwise the JWT cookie cannot be set into the domain

```{.nginxconf}
server {
    listen 443 ssl http2;
    server_name vouch.yourdomain.com;
    ssl_certificate /etc/letsencrypt/live/vouch.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vouch.yourdomain.com/privkey.pem;

    location / {
      proxy_pass http://127.0.0.1:9090;
      # be sure to pass the original host header
      proxy_set_header Host $http_host;
    }
}
```

An example of using Vouch Proxy with Nginx cacheing of the proxied validation request is available in [issue #76](https://github.com/vouch/vouch-proxy/issues/76#issuecomment-464028743).

## Running from Docker

```bash
docker run -d \
    -p 9090:9090 \
    --name vouch-proxy \
    -v ${PWD}/config:/config \
    -v ${PWD}/data:/data \
    voucher/vouch-proxy
```

The [voucher/vouch-proxy](https://hub.docker.com/r/voucher/vouch-proxy/) Docker image is an automated build on Docker Hub.  In addition to `voucher/vouch-proxy:latest` which is based on [scratch](https://docs.docker.com/samples/library/scratch/) there is an [alpine](https://docs.docker.com/samples/library/alpine/) based `voucher/vouch-proxy:alpine` as well as versioned images as `voucher/vouch-proxy:x.y.z` and `voucher/vouch-proxy:x.y.z_alpine`.

[https://hub.docker.com/r/voucher/vouch-proxy/builds/](https://hub.docker.com/r/voucher/vouch-proxy/builds/)

## Kubernetes Nginx Ingress

If you are using kubernetes with [nginx-ingress](https://github.com/kubernetes/ingress-nginx), you can configure your ingress with the following annotations (note quoting the auth-signin annotation):

```bash
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

## Troubleshooting, Support and Feature Requests

Getting the stars to align between Nginx, Vouch Proxy and your IdP can be tricky.  We want to help you get up and running as quickly as possible.  The most common problem is..

### I'm getting an infinite redirect loop which returns me to my IdP (Google/Okta/GitHub/...)

* first turn on `vouch.testing: true` and set `vouch.logLevel: debug`.  This will slow down the loop.
* the `Host:` header in the http request, the `oauth.callback_url` and the configured `vouch.domains` must all align so that the cookie that carries the JWT can be placed properly into the browser and then returned on each request
* it helps to ___think like a cookie___.
  * a cookie is set into a domain.  If you have `siteA.yourdomain.com` and `siteB.yourdomain.com` protected by Vouch Proxy, you want the Vouch Proxy cookie to be set into `.yourdomain.com`
  * if you authenticate to `vouch.yourdomain.com` the cookie will not be able to be seen by `dev.anythingelse.com`
  * unless you are using https, you should set `vouch.cookie.secure: false`
  * cookies **are** available to all ports of a domain

* please see the [issues which have been closed that mention redirect](https://github.com/vouch/vouch-proxy/issues?utf8=%E2%9C%93&q=is%3Aissue+redirect+)

### Okay, I looked at the issues and have tried some things with my configs but I still can't figure it out

* okay, please file an issue in this manner..
* run `./do.sh bug_report yourdomain.com [yourotherdomain.com]` which will create a redacted version of your config and logs
  * and follow the instructions at the end to redact your Nginx config
* paste those into [hastebin.com](https://hastebin.com/), and save it
* then [open a new issue](https://github.com/vouch/vouch-proxy/issues/new) in this repository
* or visit our IRC channel [#vouch](irc://freenode.net/#vouch) on freenode

### I really love Vouch Proxy! I wish it did XXXX

Thanks for the love, please open an issue describing your feature or idea before submitting a PR.

Please know that Vouch Proxy is not sponsored and is developed and supported on a volunteer basis.

## Project renamed to **Vouch Proxy** in January 2019

In January the project was renamed to [vouch/vouch-proxy](https://github.com/vouch/vouch-proxy) from `LassoProject/lasso`.  This is to [avoid a naming conflict](https://github.com/vouch/vouch-proxy/issues/35) with another project.

Other namespaces have been changed including the docker hub repo [lassoproject/lasso](https://hub.docker.com/r/lassoproject/lasso/) which has become [voucher/vouch-proxy](https://hub.docker.com/r/voucher/vouch-proxy)

### you should change your config to the new name as of `v0.4.0`

Existing configs for both Nginx and Vouch Proxy (lasso) should work fine.  However it would be prudent to make these minor adjustments:

in `config/config.yml`

* change "lasso:" to "vouch:"

and in your Nginx config

* change variable names "http_x_lasso_" to "http_x_vouch_"
* change the headers "X-Lasso-" to "X-Vouch-"

The examples below have been updated accordingly

Sorry for the inconvenience but we wanted to make this change at this relatively early stage of the project.

This notice will remain in the README through June 2019

## the flow of login and authentication using Google Oauth

* Bob visits `https://private.oursites.com`
* the Nginx reverse proxy...
  * recieves the request for private.oursites.com from Bob
  * uses the `auth_request` module configured for the `/validate` path
  * `/validate` is configured to `proxy_pass` requests to the authentication service at `https://vouch.oursites.com/validate`
    * if `/validate` returns...
      * 200 OK then SUCCESS allow Bob through
      * 401 NotAuthorized then
        * respond to Bob with a 302 redirect to `https://vouch.oursites.com/login?url=https://private.oursites.com`

* vouch `https://vouch.oursites.com/validate`
  * recieves the request for private.oursites.com from Bob via Nginx `proxy_pass`
  * it looks for a cookie named "oursitesSSO" that contains a JWT
  * if the cookie is found, and the JWT is valid
    * returns 200 to Nginx, which will allow access (bob notices nothing)
  * if the cookie is NOT found, or the JWT is NOT valid
    * return 401 NotAuthorized to Nginx (which forwards the request on to login)

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

Once the JWT is set, Bob will be authorized for all other sites which are configured to use `https://vouch.oursites.com/validate` from the `auth_request` Nginx module.

The next time Bob is forwarded to google for login, since he has already authorized the Vouch OAuth app, Google immediately forwards him back and sets the cookie and sends him on his merry way.  Bob may not even notice that he logged in via Vouch.
