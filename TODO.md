# TODO

* include static assets in binary
  https://github.com/shurcooL/vfsgen

* handle multiple domains
  * set the `Oauth2.config{RedirectURL}` Google callback URL dynamically based on the domain that was offered

* iterate through a list of authorized domains
  * 302 redirect to the next domain
  * set a jwt cookie into each domain
  * might slow down login

* issue tokens manually for webhooks
  * tokens are special
    * set the "issuer" field to the user
      * does user exist?
    * set expires on date in the future
    * record the token in the database
    * how do we revoke the token?
      * blacklist tokens
        * add to the conf file

* limit claims to the domain which the cookie will be placed in

  * who should get issued the token?
    * the user?
      * pobably yes
      * how do we validate the token

* move binaries under a cmd/ subdirectory

* user management
  * twitter bootstrap
  * js build environment

* additional validations (like what?)

## DONE

* add lastupdate to user, sites, team

* if the user is forwarded to /login a few times, we need to provide some explanation, and offer them an escaltion path or some way forward

* `/validate` endpoint that *any* service can connect to that validates the `X-LASSO-TOKEN` header
  * any of these are valid..
    * http cookie contents
    * X-Lasso-Token: ${TOKEN}
    * Authorization: Bearer ${TOKEN}
    * ?lasso-token=${TOKEN}

* set X-Lasso-User header passed through to the backend app
  https://stackoverflow.com/questions/19366215/setting-headers-with-nginx-auth-request-proxy#19366411

* replace gin.Cookie with gorilla.cookie

* how to handle "not authorized for domain"?
  * can nginx pass a 302 back to /login with an argument in the querystring such as..
  /login?jwt=$COOKIE
  yes it can! using the auth_request_set $variable value;
    `auth_request_set $auth_lasso_redirect $upstream_http_lasso_redirect`
  http://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request_set
  * but we're forgetting about the round trip from the state login and setting the cookie
  * we just need to detect if we've been here several times in a row, using state and then provide some kind of auth error
  * try three times, then provide auth error

* optionally compress the cookie (gzip && base64)
* use url.QueryEscape() instead of base64 https://golang.org/pkg/net/url/#QueryEscape, or maybe use QueryEscape after base64
* can we stuff all the user/sites into a 4093 byte cookie, or perhaps a cookie half that size to leave room for other cookies
  a quick test shows that a raw jwt at 1136 bytes can be gzip and base64 compressed to 471 bytes ~/tmp/jwttests
  that is probably worth doing
  http://stackoverflow.com/questions/4164276/storing-compressed-data-in-a-cookie#13675023

* validate the users' domain against `hd` from google response
* move library code under a pkg/ subdirectory

/auth validate jwt at

* is jwt in cookie
  * present?
  * valid including a user

   no.. redirect to login

* is user
  * authed for the resource?

   no.. redirect to login

* is domain
  * valid? matches authoritative domains (meedan.com, meedan.net, checkmedia.org)
  * present in the auth system
  no.. notify admin for additional assignment

/login login & auth

* offer login
* is user
  * exists?  no..
    * create user
    * assign default roles (based on domain or other heuristic)
    * notify admin for additional auth
    then..
   yes..
      * issue jwt into a cookie for each domain using an image

* add config for oauth Enpoint
  https://github.com/golang/oauth2/blob/master/github/github.go
  if endpoing is ~= google then allow 'hd' and accomodate getting User info
  * is user info for Oauth a standard form?  Probably _no_.  Going to need some interpreters. 

## leaving teams out of this for now

/admin/domains domain rights

* authorize roles
* authorize users

/admin/roles role assignment

* create roles
* assign users to roles

## interfaces

* User

## TODO web interface

* restapi
* create a special team for admins

* websocket api
  * `getusers`
  * `getteams`
  * `createteam`
  * `addusertoteam`
  * `removeuserfromteam`
  * `getsites`
  * `addsitetoteam`
  * `removesitefromteam`
  * `gettokens`
  * `createtoken`
