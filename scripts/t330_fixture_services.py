#!/usr/bin/env python3
import argparse
import socketserver
import threading
import time

from flask import Flask
from werkzeug.serving import make_server


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DropbearHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"SSH-2.0-dropbear_2024.86\r\n")


class RedisHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            request = self.request.recv(4096).lower()
        except OSError:
            return
        if b"info" not in request:
            return
        body = b"# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\nrole:master\r\n"
        self.request.sendall(b"$" + str(len(body)).encode("ascii") + b"\r\n" + body + b"\r\n+OK\r\n")


def serve(server):
    server.serve_forever(poll_interval=0.2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dropbear-port", type=int, default=22222)
    parser.add_argument("--redis-ports", default="6379,26379")
    parser.add_argument("--flask-port", type=int, default=28082)
    args = parser.parse_args()

    servers = [ThreadingTCPServer(("127.0.0.1", args.dropbear_port), DropbearHandler)]
    for value in args.redis_ports.split(","):
        servers.append(ThreadingTCPServer(("127.0.0.1", int(value)), RedisHandler))

    app = Flask("caasm-t330-fixture")

    @app.get("/")
    def index():
        return "<html><title>T330 Flask</title><body>Flask framework fixture</body></html>"

    servers.append(make_server("127.0.0.1", args.flask_port, app, threaded=True))
    for server in servers:
        threading.Thread(target=serve, args=(server,), daemon=True).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
