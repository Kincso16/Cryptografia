# keyserver.py
# Simple TCP JSON server: supports "register" and "get" commands.
import socketserver
import json
import base64
from Crypto.PublicKey import RSA
import threading
import logging

logging.basicConfig(level=logging.INFO, format='[KeyServer] %(message)s')

# In-memory registry: client_id -> PEM public key (bytes)
REGISTRY = {}

class KeyServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = b''
        # read until newline
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\n' in chunk:
                break
        try:
            msg = json.loads(data.decode('utf-8').strip())
        except Exception as e:
            logging.error("Bad request: %s", e)
            return
        cmd = msg.get('cmd')
        if cmd == 'register':
            cid = msg['client_id']
            pem = msg['pubkey_pem'].encode('utf-8')
            REGISTRY[cid] = pem
            logging.info("Registered client %s (pubkey len %d)", cid, len(pem))
            self.request.sendall(json.dumps({"status":"ok"}).encode('utf-8') + b'\n')
        elif cmd == 'get':
            cid = msg['client_id']
            pem = REGISTRY.get(cid)
            if pem:
                logging.info("Public key lookup for %s -> found", cid)
                self.request.sendall(json.dumps({"status":"ok","pubkey_pem": pem.decode('utf-8')}).encode('utf-8') + b'\n')
            else:
                logging.info("Public key lookup for %s -> NOT FOUND", cid)
                self.request.sendall(json.dumps({"status":"notfound"}).encode('utf-8') + b'\n')
        else:
            logging.info("Unknown cmd %s", cmd)
            self.request.sendall(json.dumps({"status":"error","why":"unknown cmd"}).encode('utf-8') + b'\n')

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    server = ThreadedTCPServer((args.host,args.port), KeyServerHandler)
    logging.info("KeyServer listening on %s:%d", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down")
        server.shutdown()
