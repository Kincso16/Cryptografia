# client.py
import socket
import json
import threading
import base64
import time
import logging
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from blockcipher import create_engine, Padding

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')

def send_json(host, port, obj, timeout=3):
    s = socket.create_connection((host, port), timeout)
    s.sendall((json.dumps(obj) + "\n").encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in chunk:
            break
    s.close()
    return json.loads(data.decode().strip())


class Client:
    def __init__(self, client_id:int, keyserver_host="localhost", keyserver_port=8000):
        self.id = str(client_id)
        self.host = "localhost"
        self.port = client_id

        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port

        self.logger = logging.getLogger(f"Client{self.id}")

        # RSA keys
        self.rsa = RSA.generate(2048)

        # Symmetric session parameters
        self.symmetric_key = None
        self.algorithm = None
        self.mode = None

        # Available block cipher implementations
        self.supported = [
            ("AES", "CBC"),
            ("CUSTOM", "CBC")
        ]

        # Start listener thread
        threading.Thread(target=self._listener, daemon=True).start()

    # -------------------------------------------------------------
    def pubkey_pem(self):
        return self.rsa.publickey().export_key().decode()

    def register(self):
        self.logger.info("Registering at KeyServer…")
        resp = send_json(self.keyserver_host, self.keyserver_port,
                         {"cmd": "register", "client_id": self.id,
                          "pubkey_pem": self.pubkey_pem()})
        self.logger.info(f"Register response: {resp}")

    def get_pubkey(self, peer_id):
        resp = send_json(self.keyserver_host, self.keyserver_port,
                         {"cmd": "get", "client_id": str(peer_id)})
        if resp.get("status") == "ok":
            return RSA.import_key(resp["pubkey_pem"].encode())
        return None

    # -------------------------------------------------------------
    # Listener – receives HELLO or encrypted messages
    # -------------------------------------------------------------
    def _listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(5)
        self.logger.info(f"Listening for peers on {self.host}:{self.port}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        data = b""
        while True:
            chunk = conn.recv(9000)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break

        try:
            msg = json.loads(data.decode().strip())
        except:
            conn.close()
            return

        t = msg.get("type")

        if t == "hello":
            self._handle_hello(conn, msg)
        elif t == "enc":
            self._handle_enc(conn, msg)

        conn.close()

    # -------------------------------------------------------------
    # Handle HELLO from peer
    # -------------------------------------------------------------
    def _handle_hello(self, conn, msg):
        peer_id = msg["from"]
        peer_algs = msg["algorithms"]
        peer_pub = RSA.import_key(msg["peer_pub_pem"].encode())
        enc_half = base64.b64decode(msg["half_secret"])

        self.logger.info(f"Received HELLO from {peer_id}")

        # 1) Decrypt their half
        rsa_dec = PKCS1_OAEP.new(self.rsa)
        try:
            peer_half = rsa_dec.decrypt(enc_half)
        except Exception as e:
            self.logger.error(f"Half decrypt failed: {e}")
            conn.sendall(b'{"status":"error"}\n')
            return

        # 2) Choose common algorithm
        common = None
        for a,m in self.supported:
            if [a,m] in peer_algs:
                common = (a,m)
                break

        if not common:
            conn.sendall(b'{"status":"error","why":"no common algorithm"}\n')
            return

        self.algorithm, self.mode = common
        self.logger.info(f"Chosen algorithm: {self.algorithm}/{self.mode}")

        # 3) Generate our half-key
        our_half = get_random_bytes(32)

        # 4) Derive common key — ORDERED by ID to avoid mismatch
        if int(self.id) < int(peer_id):
            comb = our_half + peer_half
        else:
            comb = peer_half + our_half

        self.symmetric_key = hashlib.sha256(comb).digest()

        # 5) Encrypt our half with peer’s RSA
        rsa_enc = PKCS1_OAEP.new(peer_pub)
        enc_resp = rsa_enc.encrypt(our_half)
        enc_b64 = base64.b64encode(enc_resp).decode()

        # 6) Send reply
        resp = {
            "status": "ok",
            "algorithm": self.algorithm,
            "mode": self.mode,
            "half_secret": enc_b64
        }
        conn.sendall((json.dumps(resp)+"\n").encode())

    # -------------------------------------------------------------
    # Handle encrypted message
    # -------------------------------------------------------------
    def _handle_enc(self, conn, msg):
        iv = base64.b64decode(msg["iv"])
        ct = base64.b64decode(msg["cipher"])

        engine = create_engine(self.algorithm, self.symmetric_key[:16],
                               self.mode, iv)

        pt = engine.decrypt(ct)
        pt = Padding.unpad(pt, engine.block_size)

        self.logger.info(f"Received encrypted message:\n{pt.decode()}")
        conn.sendall(b'{"status":"ok"}\n')

    # -------------------------------------------------------------
    # NEGOTIATION — send HELLO
    # -------------------------------------------------------------
    def negotiate(self, peer_id):
        self.logger.info(f"Negotiating with peer {peer_id}…")

        peer_pub = self.get_pubkey(peer_id)
        if not peer_pub:
            self.logger.error("Peer not registered!")
            return False

        # our half
        half = get_random_bytes(32)
        rsa_enc = PKCS1_OAEP.new(peer_pub)
        enc_half = base64.b64encode(rsa_enc.encrypt(half)).decode()

        hello = {
            "type": "hello",
            "from": self.id,
            "peer_pub_pem": self.pubkey_pem(),
            "algorithms": [list(x) for x in self.supported],
            "half_secret": enc_half
        }

        s = socket.create_connection((self.host, int(peer_id)))
        s.sendall((json.dumps(hello) + "\n").encode())

        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in chunk:
                break
        s.close()

        resp = json.loads(data.decode().strip())
        if resp.get("status") != "ok":
            self.logger.error("Negotiation failed!")
            return False

        # symmetric algorithm chosen BY PEER
        self.algorithm = resp["algorithm"]
        self.mode = resp["mode"]

        # decrypt their half
        enc_half2 = base64.b64decode(resp["half_secret"])
        rsa_dec = PKCS1_OAEP.new(self.rsa)
        their_half = rsa_dec.decrypt(enc_half2)

        # derive common key (ordered)
        if int(self.id) < int(peer_id):
            comb = half + their_half
        else:
            comb = their_half + half

        self.symmetric_key = hashlib.sha256(comb).digest()

        self.logger.info(f"Negotiation SUCCESS — using {self.algorithm}/{self.mode}")
        return True

    # -------------------------------------------------------------
    # Send encrypted message
    # -------------------------------------------------------------
    def send_encrypted(self, peer_id, text):
        iv = get_random_bytes(16)
        engine = create_engine(self.algorithm, self.symmetric_key[:16],
                               self.mode, iv)

        padded = Padding.pad(text.encode(), engine.block_size)
        ct = engine.encrypt(padded)

        msg = {
            "type": "enc",
            "from": self.id,
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ct).decode()
        }

        s = socket.create_connection((self.host, int(peer_id)))
        s.sendall((json.dumps(msg)+"\n").encode())
        s.close()
        self.logger.info(f"Sent encrypted message ({len(text)} chars)")

# ----------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", type=int, required=True)
    parser.add_argument("--keyserver", default="localhost:8000")
    args = parser.parse_args()

    ks_host, ks_port = args.keyserver.split(":")
    ks_port = int(ks_port)

    c = Client(args.id, ks_host, ks_port)
    time.sleep(1)
    c.register()

    # automatic 2-client demo
    peer = args.id + 1 if args.id % 2 == 1 else args.id - 1

    time.sleep(2)
    if c.negotiate(peer):
        msg1 = ("Hello from client " + c.id + " ") * 20
        msg2 = ("Second message " + c.id + " ") * 20

        c.send_encrypted(peer, msg1)
        time.sleep(1)
        c.send_encrypted(peer, msg2)

    while True:
        time.sleep(1)
