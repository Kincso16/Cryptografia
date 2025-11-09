import json
from typing import Optional
from dataclasses import dataclass

# AES support
try:
    from Crypto.Cipher import AES
    PYCRYPTODOME_AVAILABLE = True
except Exception:
    PYCRYPTODOME_AVAILABLE = False


# Config
@dataclass
class Config:
    block_size_bits: int
    algorithm: dict
    mode: str
    key: bytes
    iv: Optional[bytes]
    padding: str

    @staticmethod
    def load_from_file(path: str) -> 'Config':
        with open(path, 'rb') as f:
            j = json.load(f)
        b = j.get('block_size_bits', 128)
        alg = j['algorithm']
        mode = j['mode']
        key = bytes.fromhex(j['key']) if isinstance(j['key'], str) else bytes(j['key'])
        iv = None
        if 'iv' in j and j['iv'] is not None:
            iv = bytes.fromhex(j['iv']) if isinstance(j['iv'], str) else bytes(j['iv'])
        padding = j.get('padding', 'schneier-ferguson')
        return Config(b, alg, mode.upper(), key, iv, padding.lower())


# Padding
class Padding:
    @staticmethod
    def pad(block: bytes, block_size_bytes: int, mode: str) -> bytes:
        padlen = block_size_bytes - (len(block) % block_size_bytes)
        if padlen == 0:
            if mode == 'schneier-ferguson':
                padlen = block_size_bytes
            else:
                return block
        if mode == 'zero-padding':
            return block + bytes(padlen)
        elif mode == 'des-padding':
            return block + bytes([0x80]) + bytes(padlen - 1)
        elif mode == 'schneier-ferguson':
            return block + bytes([padlen]) * padlen
        else:
            raise ValueError('Unknown padding mode: ' + mode)

    @staticmethod
    def unpad(padded: bytes, block_size_bytes: int, mode: str) -> bytes:
        if mode == 'zero-padding':
            return padded.rstrip(b'\x00')
        elif mode == 'des-padding':
            idx = padded.rfind(b'\x80')
            return padded[:idx] if idx != -1 else padded
        elif mode == 'schneier-ferguson':
            if not padded:
                return padded
            n = padded[-1]
            if n <= 0 or n > block_size_bytes:
                return padded
            if padded[-n:] != bytes([n]) * n:
                return padded
            return padded[:-n]
        else:
            raise ValueError('Unknown padding mode: ' + mode)


# Base Cipher
class BlockCipher:
    def __init__(self, block_size_bytes: int):
        self.block_size = block_size_bytes

    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError


# Custom Cipher
class CustomBlockCipher(BlockCipher):
    def __init__(self, key: bytes, block_size_bytes: int, rounds: int = 6):
        super().__init__(block_size_bytes)
        self.key = key
        self.rounds = rounds

    def _round_key_stream(self, r: int) -> bytes:
        s = bytes((k ^ (r & 0xFF)) for k in self.key)
        return (s * ((self.block_size // len(s)) + 1))[:self.block_size]

    def _permute(self, b: bytearray):
        for i in range(0, len(b) - 1, 2):
            b[i], b[i + 1] = b[i + 1], b[i]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError('Invalid block size')
        state = bytearray(block)
        for r in range(self.rounds):
            rk = self._round_key_stream(r)
            for i in range(self.block_size):
                state[i] ^= rk[i]
            self._permute(state)
        return bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError('Invalid block size')
        state = bytearray(block)
        for r in reversed(range(self.rounds)):
            self._permute(state)
            rk = self._round_key_stream(r)
            for i in range(self.block_size):
                state[i] ^= rk[i]
        return bytes(state)


# AES Wrapper 
class AESBlockCipher(BlockCipher):
    def __init__(self, key: bytes, block_size_bytes: int):
        if not PYCRYPTODOME_AVAILABLE:
            raise RuntimeError('PyCryptodome not available')
        if block_size_bytes != 16:
            raise ValueError('AES block size must be 16 bytes')
        super().__init__(block_size_bytes)
        self.key = key

    def encrypt_block(self, block: bytes) -> bytes:
        return AES.new(self.key, AES.MODE_ECB).encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return AES.new(self.key, AES.MODE_ECB).decrypt(block)


#  Modes 
class ModeEngine:
    def __init__(self, cipher: BlockCipher, mode: str, iv: Optional[bytes] = None):
        self.cipher = cipher
        self.mode = mode.upper()
        self.block_size = cipher.block_size
        if iv and len(iv) != self.block_size:
            raise ValueError('IV must equal block size')
        self.iv = iv

    # ECB
    def _ecb_encrypt(self, pt): return b''.join(self.cipher.encrypt_block(pt[i:i+self.block_size]) for i in range(0, len(pt), self.block_size))
    def _ecb_decrypt(self, ct): return b''.join(self.cipher.decrypt_block(ct[i:i+self.block_size]) for i in range(0, len(ct), self.block_size))

    # CBC
    def _cbc_encrypt(self, pt):
        if not self.iv: raise ValueError('CBC requires IV')
        out, prev = bytearray(), bytearray(self.iv)
        for i in range(0, len(pt), self.block_size):
            block = bytearray(pt[i:i+self.block_size])
            for j in range(self.block_size): block[j] ^= prev[j]
            c = self.cipher.encrypt_block(bytes(block))
            out.extend(c); prev = bytearray(c)
        return bytes(out)

    def _cbc_decrypt(self, ct):
        if not self.iv: raise ValueError('CBC requires IV')
        out, prev = bytearray(), bytearray(self.iv)
        for i in range(0, len(ct), self.block_size):
            block = ct[i:i+self.block_size]
            p = bytearray(self.cipher.decrypt_block(block))
            for j in range(self.block_size): p[j] ^= prev[j]
            out.extend(p); prev = bytearray(block)
        return bytes(out)

    # CFB
    def _cfb_encrypt(self, pt):
        if not self.iv: raise ValueError('CFB requires IV')
        out, fb = bytearray(), bytearray(self.iv)
        for i in range(0, len(pt), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = pt[i:i+self.block_size]
            out_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(out_block)
            fb = bytearray(out_block) + bytes(max(0, self.block_size - len(out_block)))
        return bytes(out)

    def _cfb_decrypt(self, ct):
        if not self.iv: raise ValueError('CFB requires IV')
        out, fb = bytearray(), bytearray(self.iv)
        for i in range(0, len(ct), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = ct[i:i+self.block_size]
            p_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(p_block)
            fb = bytearray(block) + bytes(max(0, self.block_size - len(block)))
        return bytes(out)

    # OFB
    def _ofb_encrypt(self, data):
        if not self.iv: raise ValueError('OFB requires IV')
        out, fb = bytearray(), bytearray(self.iv)
        for i in range(0, len(data), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = data[i:i+self.block_size]
            out_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(out_block)
            fb = s
        return bytes(out)

    _ofb_decrypt = _ofb_encrypt

    # CTR
    def _ctr_encrypt(self, data):
        if not self.iv: raise ValueError('CTR requires IV')
        out = bytearray()
        counter = int.from_bytes(self.iv, 'big')
        for i in range(0, len(data), self.block_size):
            block = data[i:i+self.block_size]
            ctr_block = counter.to_bytes(self.block_size, 'big')
            s = bytearray(self.cipher.encrypt_block(ctr_block))
            out_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(out_block)
            counter = (counter + 1) & ((1 << (8 * self.block_size)) - 1)
        return bytes(out)

    _ctr_decrypt = _ctr_encrypt

    # Dispatchers
    def encrypt(self, data):
        return getattr(self, f"_{self.mode.lower()}_encrypt")(data)
    def decrypt(self, data):
        return getattr(self, f"_{self.mode.lower()}_decrypt")(data)


# File Processor
def process_file(config: Config, in_path: str, out_path: str, encrypt: bool):
    bs = config.block_size_bits // 8
    alg = config.algorithm.get('name', '').lower()
    if alg == 'custom':
        cipher = CustomBlockCipher(config.key, bs)
    elif alg == 'aes':
        cipher = AESBlockCipher(config.key, bs)
    else:
        raise ValueError(f'Unsupported algorithm: {alg}')

    engine = ModeEngine(cipher, config.mode, config.iv)

    with open(in_path, 'rb') as f:
        data = f.read()

    if encrypt:
        data = Padding.pad(data, bs, config.padding)
        result = engine.encrypt(data)
    else:
        result = Padding.unpad(engine.decrypt(data), bs, config.padding)

    with open(out_path, 'wb') as f:
        f.write(result)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Block cipher framework CLI")
    parser.add_argument('--encrypt', nargs=3, metavar=('CONFIG', 'IN', 'OUT'))
    parser.add_argument('--decrypt', nargs=3, metavar=('CONFIG', 'IN', 'OUT'))
    args = parser.parse_args()

    if args.encrypt:
        cfg = Config.load_from_file(args.encrypt[0])
        process_file(cfg, args.encrypt[1], args.encrypt[2], encrypt=True)
        print('Encrypted successfully.')
    if args.decrypt:
        cfg = Config.load_from_file(args.decrypt[0])
        process_file(cfg, args.decrypt[1], args.decrypt[2], encrypt=False)
        print('Decrypted successfully.')
