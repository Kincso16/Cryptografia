# client.py
# Client that:
# - generates RSA-2048 keypair
# - registers with KeyServer
# - asks KeyServer for peer's public key
# - negotiates common block cipher (we implement AES and custom)
# - exchanges half-secrets encrypted with RSA -> derive common symmetric key
# - starts a listener (peer server) to accept incoming p2p connections and accepts encrypted messages
# - connects to peer and sends >256 char encrypted messages at least twice (both directions)

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

def send_json(host,port,obj, timeout=5):
    s = socket.create_connection((host,port), timeout=timeout)
    s.sendall((json.dumps(obj)+'\n').encode('utf-8'))
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
    def __init__(self, client_id:int, listen_host='localhost', keyserver_host='localhost', keyserver_port=8000):
        self.id = str(client_id)
        self.listen_host = listen_host
        self.listen_port = client_id  # as suggested: client id == port
        self.keyserver_host = keyserver_host
        self.keyserver_port = keyserver_port
        self.rsa_key = RSA.generate(2048)
        self.logger = logging.getLogger(f'Client{self.id}')
        self.peer_engine = None
        self.symmetric_key = None
        self.chosen_alg = None
        self.chosen_mode = None
        self.iv = None

        # start peer listener
        t = threading.Thread(target=self._start_listener, daemon=True)
        t.start()

    def pubkey_pem(self):
        return self.rsa_key.publickey().export_key().decode('utf-8')

    def register(self):
        self.logger.info("Registering at KeyServer %s:%d", self.keyserver_host, self.keyserver_port)
        resp = send_json(self.keyserver_host, self.keyserver_port, {"cmd":"register","client_id": self.id, "pubkey_pem": self.pubkey_pem()})
        self.logger.info("Register response: %s", resp)

    def get_pubkey(self, peer_id):
        self.logger.info("Requesting public key for %s", peer_id)
        resp = send_json(self.keyserver_host, self.keyserver_port, {"cmd":"get","client_id": str(peer_id)})
        if resp.get('status')=='ok':
            pem = resp['pubkey_pem'].encode('utf-8')
            self.logger.info("Got public key for %s (len %d)", peer_id, len(pem))
            return RSA.import_key(pem)
        else:
            self.logger.warning("Peer %s not found", peer_id)
            return None

    def _start_listener(self):
        # listen for peer connections (receives encrypted messages)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.listen_host, self.listen_port))
        s.listen(5)
        self.logger.info("Listening for peers on %s:%d", self.listen_host, self.listen_port)
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=self._handle_peer_conn, args=(conn,addr), daemon=True)
            t.start()

    def _handle_peer_conn(self, conn, addr):
        data = b''
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data += chunk
            if b'\n' in chunk:
                break
        try:
            msg = json.loads(data.decode('utf-8').strip())
        except Exception as e:
            self.logger.error("Bad peer message: %s", e)
            conn.close(); return
        typ = msg.get('type')
        if typ == 'hello':
            # peer sends its algorithm list and mode preferences and a ciphertext half-key
            self.logger.info("Received hello from peer %s", msg.get('from'))
            peer_algs = msg['algorithms']  # list
            peer_half_b64 = msg['half_secret_b64']
            # pick first common algorithm+mode
            our_list = [("AES","CBC"),("CUSTOM","CBC")]
            chosen = None
            for a,m in our_list:
                if [a,m] in peer_algs:
                    chosen = (a,m); break
            if not chosen:
                self.logger.error("No common algorithm")
                conn.sendall((json.dumps({"status":"error","why":"no common alg"})+"\n").encode('utf-8'))
                conn.close(); return
            self.chosen_alg, self.chosen_mode = chosen
            self.logger.info("Chosen alg/mode: %s/%s", self.chosen_alg, self.chosen_mode)
            # decrypt peer's half-secret (it was encrypted with our public RSA)
            # NOTE: peer used our pubkey for encryption, so it should be decryptable with our privkey only if they used correct pubkey.
            enc = base64.b64decode(peer_half_b64)
            rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
            try:
                peer_half = rsa_cipher.decrypt(enc)
            except Exception as e:
                self.logger.error("Failed to decrypt peer half: %s", e)
                conn.close(); return
            # generate our half and send it encrypted with peer's public key (peer sent its pubkey in message)
            peer_pub_pem = msg['peer_pub_pem'].encode('utf-8')
            peer_pub = RSA.import_key(peer_pub_pem)
            our_half = get_random_bytes(32)  # 256-bit half
            rsa_peer = PKCS1_OAEP.new(peer_pub)
            enc_our_half = base64.b64encode(rsa_peer.encrypt(our_half)).decode('utf-8')
            # derive common key (concat halves and hash/truncate)
            import hashlib
            common = hashlib.sha256(peer_half + our_half).digest()  # 32 bytes
            self.symmetric_key = common[:32]  # use 256-bit key
            self.iv = get_random_bytes(16)
            self.peer_engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, self.iv)
            # reply with ack and our encrypted half
            reply = {"status":"ok","enc_our_half_b64": enc_our_half}
            conn.sendall((json.dumps(reply)+"\n").encode('utf-8'))
            self.logger.info("Sent encrypted our_half back to peer and initialized symmetric key")
        elif typ == 'enc_msg':
            # receive encrypted message: fields: iv_b64, cipher_b64
            iv = base64.b64decode(msg['iv_b64'])
            cipher_b = base64.b64decode(msg['cipher_b64'])
            # rebuild engine with stored key and this iv
            engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, iv)
            pt = engine.decrypt(cipher_b)
            pt = Padding.unpad(pt, engine.block_size)
            self.logger.info("Received encrypted message (len %d): %s", len(pt), pt.decode('utf-8', errors='replace'))
            conn.sendall((json.dumps({"status":"ok"})+"\n").encode('utf-8'))
        else:
            self.logger.warning("Unknown peer message type: %s", typ)
            conn.sendall((json.dumps({"status":"error","why":"unknown type"})+"\n").encode('utf-8'))
        conn.close()

    def connect_and_negotiate(self, peer_id):
        # 1) get peer pubkey from KeyServer
        peer_pub = self.get_pubkey(peer_id)
        if not peer_pub:
            raise RuntimeError("peer not registered")
        # 2) Build hello message: our algorithm list + our half encrypted with peer's pubkey
        our_alg_list = [ ("AES","CBC"), ("CUSTOM","CBC") ]
        peer_pub_pem = peer_pub.export_key().decode('utf-8')
        half = get_random_bytes(32)
        rsa_peer = PKCS1_OAEP.new(peer_pub)
        enc_half = base64.b64encode(rsa_peer.encrypt(half)).decode('utf-8')
        hello = {
            "type":"hello",
            "from": self.id,
            "peer_pub_pem": self.pubkey_pem(),
            "algorithms": [ list(x) for x in our_alg_list ],
            "half_secret_b64": enc_half
        }
        # connect to peer (peer_id == port), send hello
        s = socket.create_connection((self.listen_host, int(peer_id)), timeout=5)
        s.sendall((json.dumps(hello)+"\n").encode('utf-8'))
        # wait reply
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
        if resp.get('status')!='ok':
            self.logger.error("Peer hello failed: %s", resp)
            return False
        enc_our_half_b64 = resp['enc_our_half_b64']
        # decrypt the enc_our_half_b64 with our private key? No — peer returned our half encrypted with THEIR RSA pubkey.
        # Actually flow: we sent enc(half) encrypted with peer's pub; peer decrypted -> has peer_half; peer generated our_half and encrypted it with our pub and returned enc_our_half_b64.
        enc_our_half = base64.b64decode(enc_our_half_b64)
        rsa_cipher = PKCS1_OAEP.new(self.rsa_key)
        try:
            our_half_received = rsa_cipher.decrypt(enc_our_half)
        except Exception as e:
            self.logger.error("Failed to decrypt returned half: %s", e)
            return False
        # derive common key
        import hashlib
        common = hashlib.sha256(half + our_half_received).digest()
        self.symmetric_key = common[:32]
        # pick algorithm (first common from our preference)
        # For simplicity we pick AES/CBC if available
        self.chosen_alg = "AES"
        self.chosen_mode = "CBC"
        self.iv = get_random_bytes(16)
        self.peer_engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, self.iv)
        self.logger.info("Negotiation finished. Derived symmetric key and initialized engine.")
        return True

    def send_encrypted_message(self, peer_id, plaintext: str):
        if not self.peer_engine:
            raise RuntimeError("No engine")
        ptb = plaintext.encode('utf-8')
        padded = Padding.pad(ptb, self.peer_engine.block_size)
        iv = get_random_bytes(16)
        engine = create_engine(self.chosen_alg, self.symmetric_key[:16], self.chosen_mode, iv)
        cipher = engine.encrypt(padded)
        msg = {
            "type":"enc_msg",
            "from": self.id,
            "iv_b64": base64.b64encode(iv).decode('utf-8'),
            "cipher_b64": base64.b64encode(cipher).decode('utf-8')
        }
        # connect to peer and send
        s = socket.create_connection((self.listen_host, int(peer_id)), timeout=5)
        s.sendall((json.dumps(msg)+"\n").encode('utf-8'))
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
        self.logger.info("Sent encrypted message to %s, got reply: %s", peer_id, resp)

    def get_pubkey(self, peer_id):
        # wrapper to call keyserver
        return self._get_pubkey(peer_id)

    def _get_pubkey(self, peer_id):
        resp = send_json(self.keyserver_host, self.keyserver_port, {"cmd":"get","client_id": str(peer_id)})
        if resp.get('status')=='ok':
            return RSA.import_key(resp['pubkey_pem'].encode('utf-8'))
        else:
            return None

if __name__ == '__main__':
    import argparse, time
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', type=int, required=True, help='client id and listening port (e.g., 8001)')
    parser.add_argument('--keyserver', default='localhost:8000')
    args = parser.parse_args()
    ks_host, ks_port = args.keyserver.split(':')
    ks_port = int(ks_port)
    client = Client(client_id=args.id, listen_host='localhost', keyserver_host=ks_host, keyserver_port=ks_port)
    time.sleep(0.5)
    client.register()
    # Wait so other side can register in manual testing, or coordinate externally
    # If you want automatic demo: assume peer id = id+1 or id-1 as provided
    # For demo script below, we will attempt to talk to peer id 8001<->8002.
    time.sleep(1)

    # For demo: if id == 8001, connect to 8002; if 8002 connect to 8001
    if args.id % 2 == 1:
        peer = args.id + 1
    else:
        peer = args.id - 1

    # small sleep so both have registered
    time.sleep(2)
    ok = client.connect_and_negotiate(str(peer))
    if not ok:
        client.logger.error("Negotation failed")
        exit(1)
    # construct >256 char test messages
    text1 = ("Hello from client " + client.id + "! ") * 20  # enough to exceed 256 chars
    text2 = ("Replying from client " + client.id + ". ") * 20
    # Send twice
    client.send_encrypted_message(str(peer), text1)
    time.sleep(0.5)
    client.send_encrypted_message(str(peer), text2)
    time.sleep(0.5)
    # keep running to accept incoming messages
    client.logger.info("Demo done - client will keep running to accept messages. Ctrl-C to exit.")
    while True:
        time.sleep(1)
