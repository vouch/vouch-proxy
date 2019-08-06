# Advanced Authorization Using OpenResty

## What is OpenResty?
OpenResty® is a full-fledged web platform that integrates the standard Nginx core, LuaJIT, many carefully written Lua libraries, lots of high quality 3rd-party Nginx modules, and most of their external dependencies.

## Instructions

You can replace nginx with OpenResty very easily. OpenResty installation documents can be found [here](https://openresty.org/en/installation.html).

The following configuration files demonstrate a front-end proxy with multiple backend applications that are authenticated using various methods.

| File                              | Description |
| :---                              | :---        |
| conf/nginx.conf                   | Only the generic nginx config without any 'server' fields.  It includes anything at ../conf.d/*.conf |
| lua/group_auth.lua                | A lua file that validates a list of groups against the values in X-Vouch-IdP-Claims-Groups. |
| lua/user_auth.lua                 | A lua file that validates a list of users against the value in X-Vouch-User. |
| conf.d/app1.yourdomain.com.conf   | Configuration for an authenticated application at https://app1.yourdomain.com.  Uses user authorization. |
| conf.d/app2.yourdomain.com.conf   | Configuration for an authenticated application at https://app2.yourdomain.com.  Uses group authorization.  This file can be duplicated for every application you'd like to deploy. |
| conf.d/unauthenticated_app3.yourdomain.com.conf | A simple configuration for an unauthenticated application or page.  This could be a terms of service, license, or generic help page.  It could also be some application or API endpoint that you simply don't want to authenticate.  |
| conf.d/vouch.yourdomain.com.conf  | Configuration for exposing vouch at the proxy using https to a vouch instance on localhost.  This configuration supports secure cookies. |

With OpenResty and Lua it is possible to provide customized and advanced authorization on any header or claims vouch passes down.
