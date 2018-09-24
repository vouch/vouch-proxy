## questions for golang meetup

* how do I populate the context with the return code for later logging?
* where should I put my pkgs?

## TODO

* aaronpk 2017-10-04
 ‎[15:46] ‎<‎aaronpk‎>‎ so, immediate feature request is to be able to whitelist specific email addresses instead of doing domain matching for users


* aaronpk
  ‎[16:40] ‎<‎aaronpk‎>‎ sure! basically i want to redirect to https://indieauth.com instead of google auth
  ‎[16:41] ‎<‎aaronpk‎>‎ and there's an endpoint there that the plugin can use to verify the auth code and get user info
  ‎[16:44] ‎<‎aaronpk‎>‎ so being able to customize this URL or maybe even override some method to be ableto customize the handling of the verification https://github.com/bnfinet/lasso/blob/master/handlers/handlers.go#L313
  ‎[16:49] ‎<‎aaronpk‎>‎ here's the docs i was walking you through https://indieauth.com/developers
  ‎[16:53] ‎<‎bfoote‎>‎ oh that's looks pretty straight forward

* add config for oauth Enpoint
  https://github.com/golang/oauth2/blob/master/github/github.go
  if endpoing is ~= google then allow 'hd' and accomodate getting User info
  * is user info for Oauth a standard form?  Probably _no_.  Going to need some interpreters. 

* create a special team for admins

* look for the token in an "Authorization: bearer $TOKEN" header

* include static assets in binary
  https://github.com/shurcooL/vfsgen

* restapi
  * `/api/validate` endpoint that *any* service can connect to that validates the `X-LASSO-TOKEN` header

* add lastupdate to user, sites, team

* handle multiple domains
  * set the `Oauth2.config{RedirectURL}` Google callback URL dynamically based on the domain that was offered


* iterate through a list of authorized domains
  * 302 redirect to the next domain
  * set a jwt cookie into each domain
  * might slow down login

* how to handle "not authorized for domain"?
  * can nginx pass a 302 back to /login with an argument in the querystring such as..
  /login?jwt=$COOKIE
  yes it can! using the auth_request_set $variable value;
    `auth_request_set $auth_lasso_redirect $upstream_http_lasso_redirect`
  http://nginx.org/en/docs/http/ngx_http_auth_request_module.html#auth_request_set
  * but we're forgetting about the round trip from the state login and setting the cookie
  * we just need to detect if we've been here several times in a row, using state and then provide some kind of auth error
  * try three times, then provide auth error


* issue tokens manually for webhooks
  * any of these are valid..
    * http cookie contents
    * X-Lasso-Token: ${TOKEN}
    * Authorization: Bearer ${TOKEN}
    * ?lasso-token=${TOKEN}
    * TODO is this the order that these are evaluated in?
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

* if the user is forwarded to /login a few times, we need to provide some explanation, and offer them an escaltion path or some way forward

* move binaries under a cmd/ subdirectory
* user management
  * twitter bootstrap
  * js build environment
* Docker container that's not Dockerfile.fromscratch
* graphviz of Bob visit flow
* additional validations (like what?)

## DONE

* set X-Lasso-User header passed through to the backend app
  https://stackoverflow.com/questions/19366215/setting-headers-with-nginx-auth-request-proxy#19366411

* replace gin.Cookie with gorilla.cookie

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

## leaving teams out of this for now

/admin/domains domain rights

* authorize roles
* authorize users

/admin/roles role assignment

* create roles
* assign users to roles

## interfaces

* User

## TODO

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
