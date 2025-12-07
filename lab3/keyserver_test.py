import socket
import json
from Crypto.PublicKey import RSA

HOST = "localhost"
PORT = 8000

def send(obj):
    s = socket.create_connection((HOST, PORT))
    s.sendall((json.dumps(obj) + "\n").encode())
    msg = s.recv(4096).decode().strip()
    s.close()
    return json.loads(msg)

def gen():
    return RSA.generate(2048).publickey().export_key().decode()

def test_register_and_get():
    pub = gen()
    send({"cmd":"register","client_id":"9001","pubkey_pem":pub})
    r = send({"cmd":"get","client_id":"9001"})
    assert r["status"]=="ok"
    assert r["pubkey_pem"]==pub
    print("OK register+get")

def test_notfound():
    r = send({"cmd":"get","client_id":"404"})
    assert r["status"]=="notfound"
    print("OK notfound")

def test_overwrite():
    pub1 = gen()
    pub2 = gen()
    send({"cmd":"register","client_id":"7777","pubkey_pem":pub1})
    send({"cmd":"register","client_id":"7777","pubkey_pem":pub2})
    r = send({"cmd":"get","client_id":"7777"})
    assert r["pubkey_pem"] == pub2
    print("OK overwrite")

if __name__ == "__main__":
    test_register_and_get()
    test_notfound()
    test_overwrite()
    print("ALL TESTS PASSED")
