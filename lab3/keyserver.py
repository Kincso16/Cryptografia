# keyserver.py
import socketserver
import json
import logging

logging.basicConfig(level=logging.INFO, format='[KeyServer] %(message)s')

REGISTRY = {}   # client_id -> PEM public key (string)

class KeyServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b""
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break

        try:
            msg = json.loads(data.decode().strip())
        except Exception as e:
            logging.error(f"Invalid JSON: {e}")
            return

        cmd = msg.get("cmd")
        client_id = str(msg.get("client_id"))

        if cmd == "register":
            pem = msg["pubkey_pem"]
            REGISTRY[client_id] = pem
            logging.info(f"Registered client {client_id}")
            self.request.sendall(b'{"status":"ok"}\n')

        elif cmd == "get":
            pem = REGISTRY.get(client_id)
            if pem:
                logging.info(f"Lookup {client_id}: FOUND")
                resp = {"status": "ok", "pubkey_pem": pem}
            else:
                logging.info(f"Lookup {client_id}: NOT FOUND")
                resp = {"status": "notfound"}
            self.request.sendall((json.dumps(resp) + "\n").encode())

        else:
            self.request.sendall(b'{"status":"error","why":"unknown cmd"}\n')

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    server = ThreadedServer(("localhost", args.port), KeyServerHandler)
    logging.info(f"KeyServer listening on port {args.port}")
    server.serve_forever()
