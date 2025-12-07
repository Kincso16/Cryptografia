import socket
import json
from Crypto.PublicKey import RSA

HOST = "localhost"
PORT = 8000

def send(obj):
    s = socket.socket()
    s.connect((HOST, PORT))
    s.sendall((json.dumps(obj) + "\n").encode())
    data = s.recv(4096).decode().strip()
    s.close()
    return json.loads(data)

def generate_pubkey():
    key = RSA.generate(2048)
    return key.publickey().export_key().decode()

# --------------------------------------------------

def test_register_and_get():
    print("=== TEST 1: register + get ===")
    pub = generate_pubkey()

    print("Registering ID=9001")
    r = send({
        "cmd": "register",
        "client_id": 9001,
        "pubkey_pem": pub
    })
    print("Reply:", r)
    assert r["status"] == "ok"

    print("Getting ID=9001")
    r = send({
        "cmd": "get",
        "client_id": 9001
    })
    print("Reply:", r)
    assert r["status"] == "ok"
    assert r["pubkey_pem"] == pub

    print("PASS ✔\n")

# --------------------------------------------------

def test_notfound():
    print("=== TEST 2: get unknown ID ===")
    r = send({
        "cmd": "get",
        "client_id": 123456
    })
    print("Reply:", r)
    assert r["status"] == "notfound"
    print("PASS ✔\n")

# --------------------------------------------------

def test_overwrite():
    print("=== TEST 3: overwrite pubkey ===")
    pub1 = generate_pubkey()
    pub2 = generate_pubkey()

    send({"cmd": "register", "client_id": 7777, "pubkey_pem": pub1})
    send({"cmd": "register", "client_id": 7777, "pubkey_pem": pub2})

    r = send({"cmd": "get", "client_id": 7777})
    print("Reply:", r)
    assert r["status"] == "ok"
    assert r["pubkey_pem"] == pub2

    print("PASS ✔\n")

# --------------------------------------------------

if __name__ == "__main__":
    print("Running KeyServer tests...\n")
    test_register_and_get()
    test_notfound()
    test_overwrite()
    print("ALL TESTS PASSED")
