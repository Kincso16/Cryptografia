# test_block_cipher_framework.py
import os
import json
from block_cipher_framework import Config, process_file, PYCRYPTODOME_AVAILABLE

TEST_FILE_SIZE = 1024 * 1024  # 1MB
OUTPUT_FOLDER = "tests_output"  # minden teszteset ide kerül
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

algorithms = [{"name": "custom"}]
if PYCRYPTODOME_AVAILABLE:
    algorithms.append({"name": "aes"})
else:
    print('PyCryptodome not available; AES tests will be skipped')

modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]

# alap JSON konfiguráció
BASE_CONFIG = {
    "block_size_bits": 128,
    "algorithm": {"name": "aes"},  # default, felülírható
    "mode": "CBC",                 # default, felülírható
    "key": "00112233445566778899aabbccddeeff",
    "iv": "0102030405060708090a0b0c0d0e0f10",
    "padding": "schneier-ferguson"
}

def create_random_file(path, size):
    with open(path, 'wb') as f:
        f.write(os.urandom(size))

def run_case(algorithm, mode, idx=0):
    # egyedi fájlnevek minden tesztesethez
    in_file = os.path.join(OUTPUT_FOLDER, f"in_{algorithm['name']}_{mode}_{idx}.bin")
    enc_file = os.path.join(OUTPUT_FOLDER, f"enc_{algorithm['name']}_{mode}_{idx}.bin")
    dec_file = os.path.join(OUTPUT_FOLDER, f"dec_{algorithm['name']}_{mode}_{idx}.bin")
    conf_file = os.path.join(OUTPUT_FOLDER, f"conf_{algorithm['name']}_{mode}_{idx}.json")

    # generáljunk véletlenszerű input fájlt
    create_random_file(in_file, TEST_FILE_SIZE)

    # config mentése JSON-be
    conf = BASE_CONFIG.copy()
    conf['algorithm'] = algorithm
    conf['mode'] = mode
    with open(conf_file, 'w') as f:
        json.dump(conf, f)

    # config betöltése és titkosítás
    cfg = Config.load_from_file(conf_file)
    process_file(cfg, in_file, enc_file, encrypt=True)

    # visszafejtés
    cfg = Config.load_from_file(conf_file)
    process_file(cfg, enc_file, dec_file, encrypt=False)

    # ellenőrzés
    with open(in_file, 'rb') as f1, open(dec_file, 'rb') as f2:
        assert f1.read() == f2.read(), f"Mismatch for {algorithm['name']} {mode}"

def test_all():
    for idx, alg in enumerate(algorithms):
        for mode in modes:
            if alg['name'] == 'aes' and not PYCRYPTODOME_AVAILABLE:
                continue
            run_case(alg, mode, idx)
