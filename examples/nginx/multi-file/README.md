# Nginx Multi-File Configuration Example

Nginx can be configured to include conf files, allowing you to properly organize nginx configurations into individual apps.  This keeps configurations cleaner and easier to manage.

| File                      | Description |
| :---                      | :---        |
| nginx.conf                | Only the generic nginx config without any 'server' fields.  It includes anything at conf.d/*.conf |
| conf.d/app1.yourdomain.com.conf | Configuration for an authenticated application at https://app1.yourdomain.com |
| conf.d/app2.yourdomain.com.conf | Configuration for an authenticated application at https://app2.yourdomain.com.  This file can be duplicated for every application you'd like to deploy. |
| conf.d/unauthenticated_app3.yourdomain.com.conf | A simple configuration for an unauthenticated application or page.  This could be a terms of service, license, or generic help page.  It could also be some application or API endpoint that you simply don't want to authenticate.  |
| conf.d/vouch.yourdomain.com.conf | Configuration for exposing vouch at the proxy using https to a vouch instance on localhost.  This configuration supports secure cookies. | 