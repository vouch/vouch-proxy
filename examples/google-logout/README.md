# Simple Logout Solution with the Google Provider, NGINX, and Python

If you're using the [Google Identity](https://developers.google.com/identity) IdP on your app, you'll likely want to implement some sort of logout button as well. In Oauth speak, this means submitting the Google **access token** to Google's **revocation endpoint**, then clearing the Vouch session token.

## A note on tokens

There are several auth tokens used in the Vouch auth flow, and it's easy to get them mixed up. 

- **Google Identity Token**: A signed [JWT](https://jwt.io/) with identity information about the user. 
- **Google Access Token**: An opaque token which can be used to access Google APIs on behalf of the user. Vouch uses the user's **access token** to call Google's [OpenID Connect](https://developers.google.com/identity/protocols/oauth2/scopes#openid-connect) API, which serves the user's **identity token**.
- **Vouch Session Token**: A JWT-formatted session cookie which allows Vouch to continue to authenticate signed-in users without making repeated calls to Google's APIs.

## Implementation

### Revoking the access token

We can revoke the Google **Access Token** by invoking Google's [revocation endpoint](https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke). Let's create a simple Python function that accepts an access token and submits it to the revocation endpoint.

```python
import requests

def revoke(token: str) -> requests.Response:
    return requests.post('https://oauth2.googleapis.com/revoke',
        params={'token': token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})
```

Let's then wrap this function in a simple HTTP server so that we can call it from NGINX. We'll pass the **access token** via a custom `X-Access-Token` header.

```python 
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer

# Define HTTP server
class S(BaseHTTPRequestHandler):
    # Send access token to Google's revocation endpoint
    def _revoke(self, token: str) -> requests.Response:
        return requests.post('https://oauth2.googleapis.com/revoke',
            params={'token': token},
            headers = {'content-type': 'application/x-www-form-urlencoded'})

    def do_GET(self):
        token = self.headers.get("X-Ems-Access-Token")
        revoke_response = self._revoke(token)
        pass

# Startup server and set shutdown conditions
def run(server_class=HTTPServer, handler_class=S, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
```

### Invalidating the session token

The `do_GET` function calls the `_revoke` function, which sends the user's access token to the Google revocation endpoint. This is good, but we still need to invalidate the user's Vouch **session cookie**. We do this by redirecting the user to `https://vouch.xxxxxxxxxxxxxxxx.com/logout`.

The `/logout` endpoint accepts a single URL parameter: `url`, which specifies where the user should be redirected after being signed off. Let's set the `Location` header and status code of our `do_GET` function to redirect our users.

```python
# ...
    def do_GET(self):
        token = self.headers.get("X-Ems-Access-Token")
        revoke_response = self._revoke(token)
        self.send_response(302)
        self.send_header("Location", f"https://vouch.xxxxxxxxxxxxxxxx.xxx/logout?url={redirect_url}")
        self.end_headers()
        return
```

All we need to do now is run our `run` function! 

```python
# ...
if __name__ == '__main__':
    from sys import argv

    if len(argv) == 1:
        # Set default port to 8080.
        port = 8080
    else:
        port=int(argv[1])
   
    run(port=port)
```

For a complete implementation with error handling and logging, check out the `logout.py` file.

## Integrating Our Logout Server

To integrate our logout server, we'll first need to run our Python script with a daemon. I prefer **systemd** on Ubuntu. Run the following commands to get that going.

This assumes you already have Python3 installed.

```bash
# Make a logout_py user for our daemon to run as
# Ignore the "missing or non-executable shell" warning
sudo useradd -M -s /bin/nologin logout_py

# Make a server directory
sudo mkdir -p /opt/logout_py
sudo chown logout_py:logout_py /opt/logout_py

# Set up virtual environment
sudo python3 -m venv /opt/logout_py/venv
sudo su -c "source /opt/logout_py/venv/bin/activate && pip install requests"

# Move script into position
sudo cp ./logout.py /opt/logout_py/logout.py

# Move systemd service definition into position
# Make sure you edit the `PORT` variable as necessary!
sudo cp ./logout_py.service /etc/systemd/system/logout_py.service

# Start logout.py daemon
sudo systemctl daemon-reload
sudo systemctl start logout_py.service
sudo systemctl status logout_py.service
```

With that set up, we then need to create a `/logout` location in our NGINX server that forwards the appropriate headers to our **logout.py** server. See `./auth_server.conf` for variable declarations for $sub, $access_token, and $http_x_forwarded_host.

```
location /logout {
  proxy_pass http://127.0.0.1:8080;
  
  proxy_set_header X-Access-Token $access_token;

  # For logging
  proxy_set_header X-Google-Sub $sub;

  # For redirection
  proxy_set_header X-Forwarded-Host $http_host;
  # You may need to forward the host if using nested proxies
  # proxy_set_header X-Forwarded-Host $http_x_forwarded_host;
}
```

And that's it! All you need to do on the frontend is to link to `/logout`. After a quick refresh, you should see that your users need to sign in again before accessing the site.