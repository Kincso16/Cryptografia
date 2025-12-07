# blockcipher.py
# Egyszerű blokk-cipher keret: CustomBlockCipher + AES (PyCryptodome), padding, ModeEngine (ECB/CBC/CFB/OFB/CTR)
import os
from typing import Optional
from Crypto.Cipher import AES

# Padding (Schneier-Ferguson / PKCS#7 like)
class Padding:
    @staticmethod
    def pad(data: bytes, block_size: int) -> bytes:
        padlen = block_size - (len(data) % block_size)
        if padlen == 0:
            padlen = block_size
        return data + bytes([padlen]) * padlen

    @staticmethod
    def unpad(data: bytes, block_size: int) -> bytes:
        if not data:
            return data
        n = data[-1]
        if n <= 0 or n > block_size:
            return data
        if data[-n:] != bytes([n]) * n:
            return data
        return data[:-n]

# Base
class BlockCipher:
    def __init__(self, block_size: int):
        self.block_size = block_size

    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

# Custom simple cipher (toy)
class CustomBlockCipher(BlockCipher):
    def __init__(self, key: bytes, block_size: int = 16, rounds: int = 6):
        super().__init__(block_size)
        self.key = key
        self.rounds = rounds

    def _round_key_stream(self, r: int) -> bytes:
        s = bytes((k ^ (r & 0xFF)) for k in self.key)
        return (s * ((self.block_size // len(s)) + 1))[:self.block_size]

    def _permute(self, b):
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

# AES wrapper (ECB block operations)
class AESBlockCipher(BlockCipher):
    def __init__(self, key: bytes):
        super().__init__(16)
        self.key = key

    def encrypt_block(self, block: bytes) -> bytes:
        return AES.new(self.key, AES.MODE_ECB).encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return AES.new(self.key, AES.MODE_ECB).decrypt(block)

# Mode engine: uses a BlockCipher instance to implement CBC/ECB/CTR/CFB/OFB (for simplicity)
class ModeEngine:
    def __init__(self, cipher: BlockCipher, mode: str, iv: Optional[bytes] = None):
        self.cipher = cipher
        self.block_size = cipher.block_size
        self.mode = mode.upper()
        self.iv = iv

        if self.mode in ('CBC','CFB','OFB','CTR') and (iv is None or len(iv) != self.block_size):
            raise ValueError(f"{self.mode} requires IV of block size")

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.mode == 'ECB':
            return self._ecb_encrypt(plaintext)
        elif self.mode == 'CBC':
            return self._cbc_encrypt(plaintext)
        elif self.mode == 'CTR':
            return self._ctr_encrypt(plaintext)
        elif self.mode == 'CFB':
            return self._cfb_encrypt(plaintext)
        elif self.mode == 'OFB':
            return self._ofb_encrypt(plaintext)
        else:
            raise ValueError("Unknown mode")

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.mode == 'ECB':
            return self._ecb_decrypt(ciphertext)
        elif self.mode == 'CBC':
            return self._cbc_decrypt(ciphertext)
        elif self.mode == 'CTR':
            return self._ctr_decrypt(ciphertext)
        elif self.mode == 'CFB':
            return self._cfb_decrypt(ciphertext)
        elif self.mode == 'OFB':
            return self._ofb_decrypt(ciphertext)
        else:
            raise ValueError("Unknown mode")

    def _ecb_encrypt(self, pt: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(pt), self.block_size):
            out.extend(self.cipher.encrypt_block(pt[i:i+self.block_size]))
        return bytes(out)

    def _ecb_decrypt(self, ct: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(ct), self.block_size):
            out.extend(self.cipher.decrypt_block(ct[i:i+self.block_size]))
        return bytes(out)

    def _cbc_encrypt(self, pt: bytes) -> bytes:
        prev = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(pt), self.block_size):
            block = bytearray(pt[i:i+self.block_size])
            for j in range(self.block_size):
                block[j] ^= prev[j]
            c = self.cipher.encrypt_block(bytes(block))
            out.extend(c)
            prev = bytearray(c)
        return bytes(out)

    def _cbc_decrypt(self, ct: bytes) -> bytes:
        prev = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(ct), self.block_size):
            block = ct[i:i+self.block_size]
            p = bytearray(self.cipher.decrypt_block(block))
            for j in range(self.block_size):
                p[j] ^= prev[j]
            out.extend(p)
            prev = bytearray(block)
        return bytes(out)

    def _ctr_encrypt(self, data: bytes) -> bytes:
        counter = int.from_bytes(self.iv, 'big')
        out = bytearray()
        for i in range(0, len(data), self.block_size):
            ctr_block = counter.to_bytes(self.block_size, 'big')
            s = self.cipher.encrypt_block(ctr_block)
            block = data[i:i+self.block_size]
            out.extend(bytes(block[j] ^ s[j] for j in range(len(block))))
            counter = (counter + 1) & ((1 << (8*self.block_size)) - 1)
        return bytes(out)

    _ctr_decrypt = _ctr_encrypt

    def _cfb_encrypt(self, pt: bytes) -> bytes:
        fb = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(pt), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = pt[i:i+self.block_size]
            out_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(out_block)
            fb = bytearray(out_block) + bytes(max(0, self.block_size - len(out_block)))
        return bytes(out)

    def _cfb_decrypt(self, ct: bytes) -> bytes:
        fb = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(ct), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = ct[i:i+self.block_size]
            p_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(p_block)
            fb = bytearray(block) + bytes(max(0, self.block_size - len(block)))
        return bytes(out)

    def _ofb_encrypt(self, data: bytes) -> bytes:
        fb = bytearray(self.iv)
        out = bytearray()
        for i in range(0, len(data), self.block_size):
            s = bytearray(self.cipher.encrypt_block(bytes(fb)))
            block = data[i:i+self.block_size]
            out_block = bytes(block[j] ^ s[j] for j in range(len(block)))
            out.extend(out_block)
            fb = s
        return bytes(out)

    _ofb_decrypt = _ofb_encrypt

# Factory helper
def create_engine(alg_name: str, key: bytes, mode: str, iv: Optional[bytes]):
    alg = alg_name.lower()
    if alg == 'aes':
        cipher = AESBlockCipher(key)
    elif alg == 'custom':
        cipher = CustomBlockCipher(key, block_size=16)
    else:
        raise ValueError("Unknown algorithm")
    return ModeEngine(cipher, mode, iv)
