# Nginx Single-File Configuration Examples


| File                      | Description |
| :---                      | :---        |
| nginx_basic.conf          | The basic nginx configuration example.   Provides authentication for an app at https://protectedapp.yourdomain.com.  Vouch is running on vouch.yourdomain.com:9090 directly accessible.|
| nginx_with_vouch.conf     | Builds on the basic example by adding a proxy (port 80) for vouch to a vouch instance on localhost.  |
| nginx-with_vouch_ssl.conf | Builds on the basic example by adding a proxy (port 443) for vouch using https to a vouch instance on localhost.  This configuration supports secure cookies. Multiple backends can listen on port 443 at the same time when using server_name field.|