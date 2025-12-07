# client.py
import socket
import json
import threading
import base64
import time
import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from blockcipher import create_engine, Padding

logging.basicConfig(level=logging.INFO, format='[%(name)s] %(message)s')

def send_json(host, port, obj, timeout=5):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall((json.dumps(obj) + '\n').encode('utf-8'))
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'\n' in chunk:
            break
    s.close()
    return json.loads(data.decode('utf-8').strip())

class Client:
    def __init__(self, client_id: int, listen_host='localhost',
                 keyserver_host='localhost', keyserver_port=8000):

        self.id = str(client_id)
        self.listen_host = listen_host
        self.listen_port = client_id
        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port

        self.rsa_key = RSA.generate(2048)
        self.logger = logging.getLogger(f'Client{self.id}')

        self.peer_engine = None
        self.symmetric_key = None
        self.chosen_alg = None
        self.chosen_mode = None
        self.iv = None

        listener = threading.Thread(target=self._start_listener, daemon=True)
        listener.start()

    def pubkey_pem(self):
        return self.rsa_key.publickey().export_key().decode('utf-8')

    def register(self):
        self.logger.info("Registering at KeyServer…")
        resp = send_json(self.keyserver_host, self.keyserver_port, {
            "cmd": "register",
            "client_id": self.id,
            "pubkey_pem": self.pubkey_pem()
        })
        self.logger.info("Register response: %s", resp)

    def _get_pubkey(self, peer_id):
        resp = send_json(self.keyserver_host, self.keyserver_port, {
            "cmd": "get",
            "client_id": str(peer_id)
        })
        if resp.get("status") == "ok":
            return RSA.import_key(resp["pubkey_pem"].encode("utf-8"))
        return None

    def get_pubkey(self, peer_id):
        return self._get_pubkey(peer_id)

    def _start_listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(5)
        self.logger.info("Listening on %s:%d", self.listen_host, self.listen_port)

        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self._handle_peer_conn,
                                 args=(conn, addr), daemon=True)
            t.start()

    def _handle_peer_conn(self, conn, addr):
        data = b''
        while True:
            try:
                chunk = conn.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
            if b'\n' in chunk:
                break

        try:
            msg = json.loads(data.decode('utf-8').strip())
        except Exception:
            self.logger.error("Bad JSON from peer")
            conn.close()
            return

        typ = msg.get("type")
        if typ == "hello":
            self._handle_hello(msg, conn)
        elif typ == "enc_msg":
            self._handle_enc_msg(msg, conn)
        else:
            conn.sendall(json.dumps({"status": "error"}).encode() + b"\n")
        conn.close()

    def _handle_hello(self, msg, conn):
        self.logger.info("Received hello from peer %s", msg.get("from"))
        peer_algorithms = msg["algorithms"]
        peer_half_b64 = msg["half_secret_b64"]

        our_list = [("AES", "CBC"), ("CUSTOM", "CBC")]
        chosen = None
        for a, m in our_list:
            if [a, m] in peer_algorithms:
                chosen = (a, m); break

        if not chosen:
            conn.sendall(json.dumps({"status":"error","why":"no common alg"}).encode() + b"\n")
            return

        self.chosen_alg, self.chosen_mode = chosen
        self.logger.info("Chosen alg/mode: %s/%s", self.chosen_alg, self.chosen_mode)

        # decrypt peer half (they encrypted with our pub)
        rsa_self = PKCS1_OAEP.new(self.rsa_key)
        try:
            peer_half = rsa_self.decrypt(base64.b64decode(peer_half_b64))
        except Exception as e:
            self.logger.error("Failed to decrypt peer half: %s", e)
            conn.sendall(json.dumps({"status":"error","why":"decrypt failed"}).encode() + b"\n")
            return

        our_half = get_random_bytes(32)
        sender_pub_pem = msg['my_pubkey_pem'].encode('utf-8')
        sender_pub = RSA.import_key(sender_pub_pem)
        rsa_sender = PKCS1_OAEP.new(sender_pub)
        enc_our_half = base64.b64encode(rsa_sender.encrypt(our_half)).decode('utf-8')

        import hashlib
        common = hashlib.sha256(peer_half + our_half).digest()
        self.symmetric_key = common[:32]
        self.iv = get_random_bytes(16)
        self.peer_engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, self.iv)

        conn.sendall(json.dumps({"status":"ok","enc_our_half_b64": enc_our_half}).encode('utf-8') + b'\n')
        self.logger.info("Sent encrypted our_half back to peer and initialized symmetric key")

    def _handle_enc_msg(self, msg, conn):
        iv = base64.b64decode(msg["iv_b64"])
        cipher = base64.b64decode(msg["cipher_b64"])
        engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, iv)
        pt = engine.decrypt(cipher)
        pt = Padding.unpad(pt, engine.block_size)
        try:
            txt = pt.decode('utf-8')
        except Exception:
            txt = "<binary data - not utf8>"
        self.logger.info("Received encrypted message (len %d): %s", len(pt), txt)
        conn.sendall(json.dumps({"status":"ok"}).encode('utf-8') + b'\n')

    def connect_and_negotiate(self, peer_id):
        peer_pub = self.get_pubkey(peer_id)
        if not peer_pub:
            self.logger.error("Peer %s not registered!", peer_id)
            return False

        half = get_random_bytes(32)
        rsa_peer = PKCS1_OAEP.new(peer_pub)
        enc_half = base64.b64encode(rsa_peer.encrypt(half)).decode('utf-8')

        hello = {
            "type":"hello",
            "from": self.id,
            "my_pubkey_pem": self.pubkey_pem(),
            "algorithms": [["AES","CBC"], ["CUSTOM","CBC"]],
            "half_secret_b64": enc_half
        }

        s = socket.create_connection((self.listen_host, int(peer_id)), timeout=5)
        s.sendall((json.dumps(hello) + "\n").encode('utf-8'))

        data = b''
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
            if b'\n' in chunk:
                break
        s.close()

        resp = json.loads(data.decode('utf-8').strip())
        if resp.get("status") != "ok":
            return False

        enc_our_half = base64.b64decode(resp["enc_our_half_b64"])
        rsa_self = PKCS1_OAEP.new(self.rsa_key)
        our_half_received = rsa_self.decrypt(enc_our_half)

        import hashlib
        common = hashlib.sha256(half + our_half_received).digest()
        self.symmetric_key = common[:32]
        self.chosen_alg = "AES"
        self.chosen_mode = "CBC"
        self.iv = get_random_bytes(16)
        self.peer_engine = create_engine("AES", self.symmetric_key[:16], "CBC", self.iv)
        self.logger.info("Negotiation finished. Derived symmetric key and initialized engine.")
        return True

    def send_encrypted_message(self, peer_id, plaintext: str):
        plaintext_b = plaintext.encode('utf-8')
        padded = Padding.pad(plaintext_b, self.peer_engine.block_size)
        iv = get_random_bytes(16)
        engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, iv)
        cipher = engine.encrypt(padded)
        msg = {
            "type":"enc_msg",
            "from": self.id,
            "iv_b64": base64.b64encode(iv).decode('utf-8'),
            "cipher_b64": base64.b64encode(cipher).decode('utf-8')
        }
        s = socket.create_connection((self.listen_host, int(peer_id)), timeout=5)
        s.sendall((json.dumps(msg) + "\n").encode('utf-8'))
        data = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\n' in chunk:
                break
        s.close()
        resp = json.loads(data.decode('utf-8').strip())
        self.logger.info("Sent encrypted message, peer replied: %s", resp)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, type=int)
    parser.add_argument("--keyserver", default="localhost:8000")
    args = parser.parse_args()

    ks_host, ks_port = args.keyserver.split(":")
    client = Client(args.id, 'localhost', ks_host, int(ks_port))
    time.sleep(0.5)
    client.register()
    time.sleep(1)

    peer = args.id + 1 if args.id % 2 == 1 else args.id - 1
    time.sleep(2)

    if client.connect_and_negotiate(str(peer)):
        msg1 = ("Hello from client " + client.id + "! ") * 20
        msg2 = ("Replying from client " + client.id + ". ") * 20
        client.send_encrypted_message(str(peer), msg1)
        time.sleep(0.5)
        client.send_encrypted_message(str(peer), msg2)
        client.logger.info("Client ready and running.")
        while True:
            time.sleep(1)
