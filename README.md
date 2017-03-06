
# Lasso

# TODO
# we left off trying to set the cookie in cookie.go

# okay, we need a session to hold the nonce

# and maybe we should re-write this thing in echo or in go-kit

an SSO solution for an nginx reverse proxy using the [auth_request](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module

/auth validate jwt at
 - is jwt in cookie
   - present?
   - valid including a user
   no.. redirect to login
 - is user
   - authed for the resource?
   no.. redirect to login
 - is domain
   - valid? matches authoritative domains (meedan.com, meedan.net, checkmedia.org)
   - present in the auth system
   no.. notify admin for additional assignment

/login login & auth
 - offer login
 - is user
   - exists?
   no..
      - create user
      - assign default roles (based on domain or other heuristic)
      - notify admin for additional auth
      then..
   yes..
      - issue jwt into a cookie for each domain using an image

/admin/domains domain rights
  - authorize roles
  - authorize users

/admin/roles role assignment
  - create roles
  - assign users to roles

## interfaces

 * User
