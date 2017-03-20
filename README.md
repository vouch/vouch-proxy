# Lasso

## TODO

* rest api
  * `/admin/users`
    * GET list users
  * `/admin/users/${userid}`
    * GET user info
    * POST update user info
    * PUT create user
  * `/validate` endpoint that *any* service can connect to that validates the `X-LASSO-TOKEN` header
* move binaries under a cmd/ subdirectory
* user management
  * twitter bootstrap
  * js build environment
* issue tokens manually for use by services that care to consume ??
* Docker container that's not Dockerfile.fromscratch
* graphviz
* other validations (like what?)

## DONE

* validate the users' domain against `hd` from google response
* move library code under a pkg/ subdirectory

the flow of first time login

* Bob visits `https://private.oursites.com`
* nginx reverse proxy
  * recieves the request for private.oursites.com from Bob
  * uses the `auth_request` module configured for the `/authrequest` path
  * `/authrequest` is configured to `proxy_pass` requests to `https://login.oursites.com/authrequest`
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
  * respond to Bob with a 302 redirec to Google's OAuth Login form, including the "state" nonce

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

If lasso is on the same host as the nginx reverse proxy the response time from the `/authrequest` endpoint to nginx should be less than 1ms

Once the JWT is set, Bob's will be authorized for any other sites which are configured to use `https://login.oursites.com/authrequest` from the `auth_request` nginx module

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
