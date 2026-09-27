import logging
import requests

from http.server import BaseHTTPRequestHandler, HTTPServer

class S(BaseHTTPRequestHandler):
    # Send access token to Google's revocation endpoint
    def _revoke(self, token: str) -> requests.Response:
        return requests.post('https://oauth2.googleapis.com/revoke',
            params={'token': token},
            headers = {'content-type': 'application/x-www-form-urlencoded'})

    def do_GET(self):
        token = self.headers.get("X-Access-Token")
        sub = self.headers.get("X-Google-Sub")
        host = self.headers.get("X-Forwarded-Host")

        if not host:
            host = self.headers.get("Host")
        host = host.split('/')[0]

        if not sub:
            sub = "Unknown User"

        if not token:

            logging.warning("No token header supplied.")
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            self.wfile.write(f'<p>Whoops! Something went wrong. <a href="https://{host}/">Return home</a><p>'.encode())
            return

        revoke_response = self._revoke(token)
        if revoke_response.status_code >= 200 and revoke_response.status_code <= 299:
            logging.info(f"Revoked access token {sub}")
        else:
            logging.warning(f"Failed to revoke access token {sub}")

        self.send_response(302)
        self.send_header("Location", f"https://vouch.enrollmentmanagementservices.com/logout?url=https://{host}/")
        self.end_headers()
        return

def run(server_class=HTTPServer, handler_class=S, port=8020):
    logging.info(f"Attempting to serve logout.py on port {port}")
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info(f'Serving on port {port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping logout.py\n')

if __name__ == '__main__':
    from sys import argv

    #logging.basicConfig(level=logging.INFO)

    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Logout.py")

    if len(argv) == 1:
        logging.warning("Port not specified. Starting on the default 8080.")
        logging.warning("To choose a different port, rerun this script with the desired port as the first CLI argument.")
        port = 8080
    else:
        port=int(argv[1])
   
    run(port=port)
