"""Deliberately weak local target for demoing secscan. Binds to 127.0.0.1 only."""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"""<html><body><h1>Demo Shop</h1>
<a href="/orders/1001">My order</a> <a href="/profile?user_id=7">Profile</a>
<a href="/search?q=shoes&page=1">Search</a>
<form action="/login" method="post"><input name="username"><input name="password"></form>
</body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.0"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "session=abc123; Path=/")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), H).serve_forever()
