# Vouch Proxy

[![GitHub stars](https://img.shields.io/github/stars/vouch/vouch-proxy.svg)](https://github.com/vouch/vouch-proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/vouch/vouch-proxy)](https://goreportcard.com/report/github.com/vouch/vouch-proxy)
[![MIT license](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/vouch/vouch-proxy/blob/master/LICENSE)
[![Docker pulls](https://img.shields.io/docker/pulls/voucher/vouch-proxy.svg)](https://hub.docker.com/r/voucher/vouch-proxy/)
[![GitHub version](https://img.shields.io/github/v/tag/vouch/vouch-proxy.svg?sort=semver&color=green)](https://github.com/vouch/vouch-proxy)

An SSO solution for Nginx using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module. Vouch Proxy can protect all of your websites at once.

Vouch Proxy supports many OAuth and OIDC login providers and can enforce authentication to...

- Google
- [GitHub](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/)
- GitHub Enterprise
- [IndieAuth](https://indieauth.spec.indieweb.org/)
- [Okta](https://developer.okta.com/blog/2018/08/28/nginx-auth-request)
- [ADFS](https://github.com/vouch/vouch-proxy/pull/68)
- [Azure AD](https://github.com/vouch/vouch-proxy/issues/290)
- [Alibaba / Aliyun iDaas](https://github.com/vouch/vouch-proxy/issues/344)
- [AWS Cognito](https://github.com/vouch/vouch-proxy/issues/105)
- [Gitea](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example_gitea)
- Keycloak
- [OAuth2 Server Library for PHP](https://github.com/vouch/vouch-proxy/issues/99)
- [HomeAssistant](https://developers.home-assistant.io/docs/en/auth_api.html)
- [OpenStax](https://github.com/vouch/vouch-proxy/pull/141)
- [Nextcloud](https://docs.nextcloud.com/server/latest/admin_manual/configuration_server/oauth2.html)
- most other OpenID Connect (OIDC) providers

Please do let us know when you have deployed Vouch Proxy with your preffered IdP or library so we can update the list.

If Vouch is running on the same host as the Nginx reverse proxy the response time from the `/validate` endpoint to Nginx should be less than 1ms

---

## Table of Contents

- [What Vouch Proxy Does...](#what-vouch-proxy-does)
- [Installation and Configuration](#installation-and-configuration)
- [Configuring Vouch Proxy using Environmental Variables](#configuring-vouch-proxy-using-environmental-variables)
- [More advanced configurations](#more-advanced-configurations)
  - [Scopes and Claims](#scopes-and-claims)
- [Running from Docker](#running-from-docker)
- [Kubernetes Nginx Ingress](#kubernetes-nginx-ingress)
- [Compiling from source and running the binary](#compiling-from-source-and-running-the-binary)
- [/login and /logout endpoint redirection](#-login-and--logout-endpoint-redirection)
- [Troubleshooting, Support and Feature Requests](#troubleshooting--support-and-feature-requests--read-this-before-submitting-an-issue-at-github-)
  (Read this before submitting an issue at GitHub)
  - [I'm getting an infinite redirect loop which returns me to my IdP (Google/Okta/GitHub/...)](#i-m-getting-an-infinite-redirect-loop-which-returns-me-to-my-idp--google-okta-github--)
  - [Okay, I looked at the issues and have tried some things with my configs but it's still not working](#okay--i-looked-at-the-issues-and-have-tried-some-things-with-my-configs-but-it-s-still-not-working)
  - [submitting a Pull Request for a new feature](#submitting-a-pull-request-for-a-new-feature)
- [Advanced Authorization Using OpenResty](#advanced-authorization-using-openresty)
- [The flow of login and authentication using Google Oauth](#the-flow-of-login-and-authentication-using-google-oauth)

---

## What Vouch Proxy Does...

Vouch Proxy (VP) forces visitors to login and authenticate with an [IdP](https://en.wikipedia.org/wiki/Identity_provider) (such as one of the services listed above) before allowing them access to a website.

![Vouch Proxy protects websites](https://github.com/vouch/vouch-proxy/blob/master/examples/nginx-vouch-private_simple.png?raw=true)

VP can also be used as a Single Sign On (SSO) solution to protect all web applications in the same domain.

![Vouch Proxy is a Single Sign On solution](https://github.com/vouch/vouch-proxy/blob/master/examples/nginx-vouch-private_appA_appB_appC.png?raw=true)

After a visitor logs in Vouch Proxy allows access to the protected websites for several hours. Every request is checked by VP to ensure that it is valid.

VP can send the visitor's email, name and other information which the IdP provides (including access tokens) to the web application as HTTP headers. VP can be used to replace application user management entirely.

## Installation and Configuration

Vouch Proxy relies on the ability to share a cookie between the Vouch Proxy server and the application it's protecting. Typically this will be done by running Vouch on a subdomain such as `vouch.yourdomain.com` with apps running at `app1.yourdomain.com` and `app2.yourdomain.com`. The protected domain is `.yourdomain.com` and the Vouch Proxy cookie must be set in this domain by setting [vouch.domains](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example#L23-L33) to include `yourdomain.com` or sometimes by setting [vouch.cookie.domain](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example#L81-L82) to `yourdomain.com`.

- `cp ./config/config.yml_example_$OAUTH_PROVIDER ./config/config.yml`
- create OAuth credentials for Vouch Proxy at [google](https://console.developers.google.com/apis/credentials) or [github](https://developer.github.com/apps/building-integrations/setting-up-and-registering-oauth-apps/about-authorization-options-for-oauth-apps/), etc
  - be sure to direct the callback URL to the Vouch Proxy `/auth` endpoint
- configure Nginx...

The following Nginx config assumes..

- Nginx, `vouch.yourdomain.com` and `protectedapp.yourdomain.com` are running on the same server
- both domains are served as `https` and have valid certs (if not, change to `listen 80` and set [vouch.cookie.secure](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example#L84-L85) to `false`)

```{.nginxconf}
server {
    listen 443 ssl http2;
    server_name protectedapp.yourdomain.com;
    root /var/www/html/;

    ssl_certificate /etc/letsencrypt/live/protectedapp.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/protectedapp.yourdomain.com/privkey.pem;

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

      # optionally add X-Vouch-IdP-Claims-* custom claims you are tracking
      #    auth_request_set $auth_resp_x_vouch_idp_claims_groups $upstream_http_x_vouch_idp_claims_groups;
      #    auth_request_set $auth_resp_x_vouch_idp_claims_given_name $upstream_http_x_vouch_idp_claims_given_name;
      # optinally add X-Vouch-IdP-AccessToken or X-Vouch-IdP-IdToken
      #    auth_request_set $auth_resp_x_vouch_idp_accesstoken $upstream_http_x_vouch_idp_accesstoken;
      #    auth_request_set $auth_resp_x_vouch_idp_idtoken $upstream_http_x_vouch_idp_idtoken;

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
      # you may need to set these variables in this block as per https://github.com/vouch/vouch-proxy/issues/26#issuecomment-425215810
      #    auth_request_set $auth_resp_x_vouch_user $upstream_http_x_vouch_user
      #    auth_request_set $auth_resp_x_vouch_idp_claims_groups $upstream_http_x_vouch_idp_claims_groups;
      #    auth_request_set $auth_resp_x_vouch_idp_claims_given_name $upstream_http_x_vouch_idp_claims_given_name;

      # set user header (usually an email)
      proxy_set_header X-Vouch-User $auth_resp_x_vouch_user;
      # optionally pass any custom claims you are tracking
      #     proxy_set_header X-Vouch-IdP-Claims-Groups $auth_resp_x_vouch_idp_claims_groups;
      #     proxy_set_header X-Vouch-IdP-Claims-Given_Name $auth_resp_x_vouch_idp_claims_given_name;
      # optionally pass the accesstoken or idtoken
      #     proxy_set_header X-Vouch-IdP-AccessToken $auth_resp_x_vouch_idp_accesstoken;
      #     proxy_set_header X-Vouch-IdP-IdToken $auth_resp_x_vouch_idp_idtoken;
    }
}

```

If Vouch is configured behind the **same** nginx reverseproxy ([perhaps so you can configure ssl](https://github.com/vouch/vouch-proxy/issues/64#issuecomment-461085139)) be sure to pass the `Host` header properly, otherwise the JWT cookie cannot be set into the domain

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

Additional Nginx configurations can be found in the [examples](https://github.com/vouch/vouch-proxy/tree/master/examples) directory.

## Configuring Vouch Proxy using Environmental Variables

Here's a minimal setup using Google OAuth...

```bash
VOUCH_DOMAINS=yourdomain.com \
  OAUTH_PROVIDER=google \
  OAUTH_CLIENT_ID=1234 \
  OAUTH_CLIENT_SECRET=secretsecret \
  OAUTH_CALLBACK_URL=https://vouch.yourdomain.com/auth \
  ./vouch-proxy
```

Environmental variable names are documented in [config/config.yml_example](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example)

All lists with multiple values must be comma separated: `VOUCH_DOMAINS="yourdomain.com,yourotherdomain.com"`

The variable `VOUCH_CONFIG` can be used to set an alternate location for the configuration file. `VOUCH_ROOT` can be used to set an alternate root directory for Vouch Proxy to look for support files.

## More advanced configurations

All Vouch Proxy configuration items are documented in [config/config.yml_example](https://github.com/vouch/vouch-proxy/blob/master/config/config.yml_example)

- [cacheing of the Vouch Proxy validation response in Nginx](https://github.com/vouch/vouch-proxy/issues/76#issuecomment-464028743)
- [handleing `OPTIONS` requests when protecting an API with Vouch Proxy](https://github.com/vouch/vouch-proxy/issues/216)
- [validation by GitHub Team or GitHub Org](https://github.com/vouch/vouch-proxy/pull/205)
- [running on a Raspberry Pi using the ARM based Docker image](https://github.com/vouch/vouch-proxy/pull/247)
- [Kubernetes architecture post ingress](https://github.com/vouch/vouch-proxy/pull/263#issuecomment-628297832)
- [set `HTTP_PROXY` to relay Vouch Proxy IdP requests through an outbound proxy server](https://github.com/vouch/vouch-proxy/issues/291)
- [Reverse Proxy for Google Cloud Run Services](https://github.com/karthikv2k/oauth_reverse_proxy)
- [Enable native TLS in Vouch Proxy](https://github.com/vouch/vouch-proxy/pull/332#issue-522612010)
- [FreeBSD support](https://github.com/vouch/vouch-proxy/issues/368)

Please do help us to expand this list.

### Scopes and Claims

With Vouch Proxy you can request various `scopes` (standard and custom) to obtain more information about the user or gain access to the provider's APIs. Internally, Vouch Proxy launches a requests to `user_info_url` after successful authentication. From the provider's response the required `claims` are extracted and stored in the vouch cookie.

⚠️ **Additional claims and tokens will be added to the VP cookie and can make it large**

The VP cookie may get split up into several cookies, but if you need it, you need it. Large cookies and headers require Nginx to be configured with larger buffers. See [large_client_header_buffers](http://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers) and [proxy_buffer_size](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size) for more information.

#### Setup `scopes` and `claims` in Vouch Proxy with Nginx

0. Configure Vouch Proxy for Nginx and your IdP as normal (See: [Installation and Configuration](#installation-and-configuration))

1. Set the necessary `scope`s in the `oauth` section of the vouch-proxy `config.yml` ([example config](config/config.yml_example_scopes_and_claims))
   1. set `idtoken: X-Vouch-IdP-IdToken` in the `headers` section of vouch-proxy's `config.yml`
   2. log in and call the `/validate` endpoint in a modern browser
   3. check the response header for a `X-Vouch-IdP-IdToken` header
   4. copy the value of the header into the debugger at https://jwt.io/ and ensure that the necessary claims are part of the jwt
   5. if they are not, you need to adjust the `scopes` in the `oauth` section of your `config.yml` or reconfigure your oauth provider
2. Set the necessary `claims` in the `header` section of the vouch-proxy `config.yml`
   1. log in and call the `/validate` endpoint in a modern browser
   2. check the response headers for headers of the form `X-Vouch-Idp-Claims-<ClaimName>`
   3. If they are not there clear your cookies and cached browser data
   4. 🐞 If they are still not there but exist in the jwt (esp. custom claims) there might be a bug
   5. remove the `idtoken: X-Vouch-IdP-IdToken` from the `headers` section of vouch-proxy's `config.yml` if you don't need it
3. Use `auth_request_set` after `auth_request` inside the protected location in the nginx [`server.conf`](examples/nginx/nginx_scopes_and_claims.conf)
4. Consume the claim ([example nginx config](examples/nginx/nginx_scopes_and_claims.conf))

## Running from Docker

```bash
docker run -d \
    -p 9090:9090 \
    --name vouch-proxy \
    -v ${PWD}/config:/config \
    voucher/vouch-proxy
```

or

```bash
docker run -d \
    -p 9090:9090 \
    --name vouch-proxy \
    -e VOUCH_DOMAINS=yourdomain.com \
    -e OAUTH_PROVIDER=google \
    -e OAUTH_CLIENT_ID=1234 \
    -e OAUTH_CLIENT_SECRET=secretsecret \
    -e OAUTH_CALLBACK_URL=https://vouch.yourdomain.com/auth \
    voucher/vouch-proxy
```

Automated container builds for each Vouch Proxy release are available from [Docker Hub](https://hub.docker.com/r/voucher/vouch-proxy/). Each release produces..

- `voucher/vouch-proxy:latest`
- `voucher/vouch-proxy:x.y.z`
- `voucher/vouch-proxy:alpine`
- `voucher/vouch-proxy:alpine-x.y.z`
- `voucher/vouch-proxy:latest-arm`

## Kubernetes Nginx Ingress

If you are using kubernetes with [nginx-ingress](https://github.com/kubernetes/ingress-nginx), you can configure your ingress with the following annotations (note quoting the `auth-signin` annotation):

```bash
    nginx.ingress.kubernetes.io/auth-signin: "https://vouch.yourdomain.com/login?url=$scheme://$http_host$request_uri&vouch-failcount=$auth_resp_failcount&X-Vouch-Token=$auth_resp_jwt&error=$auth_resp_err"
    nginx.ingress.kubernetes.io/auth-url: https://vouch.yourdomain.com/validate
    nginx.ingress.kubernetes.io/auth-response-headers: X-Vouch-User
    nginx.ingress.kubernetes.io/auth-snippet: |
      # these return values are used by the @error401 call
      auth_request_set $auth_resp_jwt $upstream_http_x_vouch_jwt;
      auth_request_set $auth_resp_err $upstream_http_x_vouch_err;
      auth_request_set $auth_resp_failcount $upstream_http_x_vouch_failcount;
```

Helm Charts are maintained by [halkeye](https://github.com/halkeye) and are available at [https://github.com/halkeye-helm-charts/vouch](https://github.com/halkeye-helm-charts/vouch) / [https://halkeye.github.io/helm-charts/](https://halkeye.github.io/helm-charts/)

## Compiling from source and running the binary

```bash
  ./do.sh goget
  ./do.sh build
  ./vouch-proxy
```

## /login and /logout endpoint redirection

As of `v0.11.0` additional checks are in place to reduce [the attack surface of url redirection](https://blog.detectify.com/2019/05/16/the-real-impact-of-an-open-redirect/).

### /login?url=POST_LOGIN_URL

The passed URL...

- must start with either `http` or `https`
- must have a domain overlap with either a domain in the `vouch.domains` list or the `vouch.cookie.domain` (if either of those are configured)
- cannot have a parameter which includes a URL to [prevent URL chaining attacks](https://hackerone.com/reports/202781)

### /logout?url=NEXT_URL

The Vouch Proxy `/logout` endpoint accepts a `url` parameter in the query string which can be used to `302` redirect a user to your orignal OAuth provider/IDP/OIDC provider's [revocation_endpoint](https://tools.ietf.org/html/rfc7009)

```bash
    https://vouch.oursites.com/logout?url=https://oauth2.googleapis.com/revoke
```

this url must be present in the configuration file on the list `vouch.post_logout_redirect_uris`

```yaml
# in order to prevent redirection attacks all redirected URLs to /logout must be specified
# the URL must still be passed to Vouch Proxy as https://vouch.yourdomain.com/logout?url=${ONE OF THE URLS BELOW}
post_logout_redirect_uris:
  # your apps login page
  - http://.yourdomain.com/login
  # your IdPs logout enpoint
  # from https://accounts.google.com/.well-known/openid-configuration
  - https://oauth2.googleapis.com/revoke
  # you may be daisy chaining to your IdP
  - https://myorg.okta.com/oauth2/123serverid/v1/logout?post_logout_redirect_uri=http://myapp.yourdomain.com/login
```

Note that your IdP will likely carry their own, separate `post_logout_redirect_uri` list.

logout resources..

- [Google](https://developers.google.com/identity/protocols/OAuth2WebServer#tokenrevoke)
- [Okta](https://developer.okta.com/docs/api/resources/oidc#logout)
- [Auth0](https://auth0.com/docs/logout/guides/logout-idps)

## Troubleshooting, Support and Feature Requests (Read this before submitting an issue at GitHub)

Getting the stars to align between Nginx, Vouch Proxy and your IdP can be tricky. We want to help you get up and running as quickly as possible. The most common problem is..

### I'm getting an infinite redirect loop which returns me to my IdP (Google/Okta/GitHub/...)

Double check that you are running Vouch Proxy and your apps on a common domain that can share cookies. For example, `vouch.yourdomain.com` and `app.yourdomain.com` can share cookies on the `.yourdomain.com` domain. (It will not work if you are trying to use `vouch.yourdomain.org` and `app.yourdomain.net`.)

You may need to explicitly define the domain that the cookie should be set on. You can do this in the config file by setting the option:

```yaml
vouch:
  cookie:
    # force the domain of the cookie to set
    domain: yourdomain.com
```

If you continue to have trouble, try the following:

- **turn on `vouch.testing: true`**. This will slow down the loop.
- set `vouch.logLevel: debug`.
- the `Host:` header in the http request, the `oauth.callback_url` and the configured `vouch.domains` must all align so that the cookie that carries the JWT can be placed properly into the browser and then returned on each request
- it helps to **_think like a cookie_**.

  - a cookie is set into a domain. If you have `siteA.yourdomain.com` and `siteB.yourdomain.com` protected by Vouch Proxy, you want the Vouch Proxy cookie to be set into `.yourdomain.com`
  - if you authenticate to `vouch.yourdomain.com` the cookie will not be able to be seen by `dev.anythingelse.com`
  - unless you are using https, you should set `vouch.cookie.secure: false`
  - cookies **are** available to all ports of a domain

- please see the [issues which have been closed that mention redirect](https://github.com/vouch/vouch-proxy/issues?utf8=%E2%9C%93&q=is%3Aissue+redirect+)

### Okay, I looked at the issues and have tried some things with my configs but it's still not working

Please [submit a new issue](https://github.com/vouch/vouch-proxy/issues) in the following fashion..

TLDR:

- set `vouch.testing: true`
- set `vouch.logLevel: debug`
- conduct a full round trip of `./vouch-proxy` capturing the output..
  - VP startup
  - `/validate`
  - `/login` - even if the error is here
  - `/auth`
  - `/validate` - capture everything
- put all your logs and config in a `gist`.
- `./do.sh bug_report` is your friend

#### But read this anyways because we'll ask you to read it if you don't follow these instruction. :)

- **turn on `vouch.testing: true`** and set `vouch.logLevel: debug`.
- use a [gist](https://gist.github.com/) or another **paste service** such as [hasteb.in](https://hasteb.in/). **_DO NOT PUT YOUR LOGS AND CONFIG INTO THE GITHUB ISSUE_**. Using a paste service is important as it will maintain spacing and will provide line numbers and formatting. We are hunting for needles in haystacks with setups with several moving parts, these features help considerably. Paste services save your time and our time and help us to help you quickly. You're more likely to get good support from us in a timely manner by following this advice.
- run `./do.sh bug_report secretdomain.com secretpass [anothersecret..]` which will create a redacted version of your config and logs removing each of those strings
  - and follow the instructions at the end to redact your Nginx config
- all of those go into a [gist](https://gist.github.com/)
- then [open a new issue](https://github.com/vouch/vouch-proxy/issues/new) in this repository
- or visit our IRC channel [#vouch](irc://freenode.net/#vouch) on freenode

A bug report can be generated from a docker environment using the `voucher/vouch-proxy:alpine` image...

```!bash
docker run --name vouch_proxy -v $PWD/config:/config -v $PWD/certs:/certs -it --rm --entrypoint /do.sh voucher/vouch-proxy:alpine bug_report yourdomain.com anotherdomain.com someothersecret
```

### submitting a Pull Request for a new feature

I really love Vouch Proxy! I wish it did XXXX...

Please make a proposal before you spend your time and our time integrating a new feature.

Code contributions should..

- include unit tests and in some cases end-to-end tests
- be formatted with `go fmt`, checked with `go vet` and other common go tools
- not break existing setups without a clear reason (usually security related)
- and generally be discussed beforehand in a GitHub issue

For larger contributions or code related to a platform that we don't currently support we will ask you to commit to supporting the feature for an agreed upon period. Invariably someone will pop up here with a question and we want to be able to support these requests.

## Advanced Authorization Using OpenResty

OpenResty® is a full-fledged web platform that integrates the standard Nginx core, LuaJIT, many carefully written Lua libraries, lots of high quality 3rd-party Nginx modules, and most of their external dependencies.

You can replace nginx with [OpenResty](https://openresty.org/en/installation.html) fairly easily.

With OpenResty and Lua it is possible to provide customized and advanced authorization on any header or claims vouch passes down.

OpenResty and configs for a variety of scenarios are available in the [examples](https://github.com/vouch/vouch-proxy/tree/master/examples) directory.

## The flow of login and authentication using Google Oauth

- Bob visits `https://private.oursites.com`
- the Nginx reverse proxy...

  - recieves the request for private.oursites.com from Bob
  - uses the `auth_request` module configured for the `/validate` path
  - `/validate` is configured to `proxy_pass` requests to the authentication service at `https://vouch.oursites.com/validate`
    - if `/validate` returns...
      - 200 OK then SUCCESS allow Bob through
      - 401 NotAuthorized then
        - respond to Bob with a 302 redirect to `https://vouch.oursites.com/login?url=https://private.oursites.com`

- Vouch Proxy `https://vouch.oursites.com/validate`

  - recieves the request for private.oursites.com from Bob via Nginx `proxy_pass`
  - looks for a cookie named "oursitesSSO" that contains a JWT
  - if the cookie is found, and the JWT is valid
    - returns `200 OK` to Nginx, which will allow access (bob notices nothing)
  - if the cookie is NOT found, or the JWT is NOT valid
    - return `401 NotAuthorized` to Nginx (which forwards the request on to login)

- Bob is first forwarded briefly to `https://vouch.oursites.com/login?url=https://private.oursites.com`

  - clears out the cookie named "oursitesSSO" if it exists
  - generates a nonce and stores it in session variable \$STATE
  - stores the url `https://private.oursites.com` from the query string in session variable `$requestedURL`
  - respond to Bob with a 302 redirect to Google's OAuth Login form, including the `$STATE` nonce

- Bob logs into his Google account using Oauth

  - after successful login
  - Google responds to Bob with a 302 redirect to `https://vouch.oursites.com/auth?state=$STATE`

- Bob is forwarded to `https://vouch.oursites.com/auth?state=$STATE`
  - if the \$STATE nonce from the url matches the session variable "state"
  - make a "third leg" request of Google (server to server) to exchange the OAuth code for Bob's user info including email address bob@oursites.com
  - if the email address matches the domain oursites.com (it does)
    - issue bob a JWT in the form of a cookie named "oursitesSSO"
    - retrieve the session variable `$requestedURL` and 302 redirect bob back to `https://private.oursites.com`

Note that outside of some innocuos redirection, Bob only ever sees `https://private.oursites.com` and the Google Login screen in his browser. While Vouch does interact with Bob's browser several times, it is just to set cookies, and if the 302 redirects work properly Bob will log in quickly.

Once the JWT is set, Bob will be authorized for all other sites which are configured to use `https://vouch.oursites.com/validate` from the `auth_request` Nginx module.

The next time Bob is forwarded to google for login, since he has already authorized the Vouch Proxy OAuth app, Google immediately forwards him back and sets the cookie and sends him on his merry way. In some browsers such as Chrome, Bob may not even notice that he logged in using Vouch Proxy.
