# Lasso

## TODO

* issue tokens manually for webhooks
  * tokens are special, they don't expire, they include an additional claim
    * do they have to be so large?
      * otherwise we do the database lookup
  * any of these are valid..
  * TODO is this the order that these are evaluated in?
    * http cookie contents
    * X-Lasso-Token: ${TOKEN}
    * Authorization: Bearer ${TOKEN}
    * ?lasso-token=${TOKEN}

  * who should get issued the token?
    * the user?
      * pobably yes
      * how do we validate the token
        * its just a jwt with an expires on date in the future
      * how do we expire the token?
        * blacklist tokens
        * does user exist?

* rest api
  * tempting to do protobuf or something but lets just do rest for now
  * `/api/users`
    * GET list users
  * `/api/users/${userid}`
    * GET user info
    * POST update user info
    * PUT create user
  * `/api/validate` endpoint that *any* service can connect to that validates the `X-LASSO-TOKEN` header
* move binaries under a cmd/ subdirectory
* user management
  * twitter bootstrap
  * js build environment
* Docker container that's not Dockerfile.fromscratch
* graphviz of Bob visit flow
* other validations (like what?)

* optionally compress the cookie (gzip && base64)
* use url.QueryEscape() instead of base64 https://golang.org/pkg/net/url/#QueryEscape, or maybe use QueryEscape after base64
* can we stuff all the user/sites into a 4093 byte cookie, or perhaps a cookie half that size to leave room for other cookies
  a quick test shows that a raw jwt at 1136 bytes can be gzip and base64 compressed to 471 bytes ~/tmp/jwttests
  http://stackoverflow.com/questions/4164276/storing-compressed-data-in-a-cookie#13675023
  that is probably worth doing

## DONE

* validate the users' domain against `hd` from google response
* move library code under a pkg/ subdirectory

the flow of first time login

* Bob visits `https://private.oursites.com`
* the nginx reverse proxy...
  * recieves the request for private.oursites.com from Bob
  * uses the `auth_request` module configured for the `/authrequest` path
  * `/authrequest` is configured to `proxy_pass` requests to the authentication service at `https://login.oursites.com/authrequest`
    * if `/authrequest` returns...
      * 200 OK then SUCCESS allow Bob through
      * 401 NotAuthorized then
        * respond to Bob with a 302 redirect to `https://login.oursites.com/login?url=https://private.oursites.com`

* nginx contacts `https://login.oursites.com/authrequest`
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

Once the JWT is set, Bob's will be authorized for any other sites which are configured to use `https://login.oursites.com/authrequest` from the `auth_request` nginx module.

The next time Bob is forwarded to google for login, since he has already authorized the site it immediately forwards him back and sets the cookie and sends him on his merry way.

If lasso is on the same host as the nginx reverse proxy the response time from the `/authrequest` endpoint to nginx should be less than 1ms


an SSO solution for an nginx reverse proxy using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module

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
