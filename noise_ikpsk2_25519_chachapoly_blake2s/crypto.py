
from functools import partial
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend


class KeyPair25519:
    def __init__(self, private: X25519PrivateKey=None, public: X25519PublicKey=None, public_bytes: bytes=None):
        self.private = private
        self.public = public
        self.public_bytes = public_bytes

    @classmethod
    def from_private(cls, data: bytes) -> 'KeyPair25519':
        private = X25519PrivateKey.from_private_bytes(data)
        public = private.public_key()
        return cls(private, public, public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @classmethod
    def from_public(cls, data: bytes) -> 'KeyPair25519':
        public = X25519PublicKey.from_public_bytes(data)
        return cls(None, public, public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


class ED25519:
    """
    Implemented as per Noise Protocol specification - paragraph 4.1.
    """
    DHLEN = 32

    @classmethod
    def generate_keypair(cls) -> KeyPair25519:
        private = X25519PrivateKey.generate()
        public = private.public_key()
        return KeyPair25519(private, public, public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    @classmethod
    def dh(cls, private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
        if not isinstance(private_key, X25519PrivateKey) or not isinstance(public_key, X25519PublicKey):
            raise Exception('NoiseValueError: Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances')
        return private_key.exchange(public_key)


class ChaChaPoly:
    """
    Implemented as per Noise Protocol specification - paragraph 4.2.
    """
    NONCELEN = 8
    MAXNONCE = 2 ** 64 - 1

    def __init__(self, k: bytes):
        self.cipher = ChaCha20Poly1305(k)

    def _format_nonce(self, n: int) -> bytes:
        # padded to 12-bytes
        return b'\x00\x00\x00\x00' + n.to_bytes(self.NONCELEN, 'little')

    def encrypt(self, k: bytes, n: int, ad: bytes, plaintext: bytes) -> bytes:
        if n == self.MAXNONCE:
            raise Exception('NoiseMaxNonceError: Nonce has depleted!')
        return self.cipher.encrypt(self._format_nonce(n), plaintext, ad)

    def decrypt(self, k: bytes, n: int, ad: bytes, ciphertext: bytes) -> bytes:
        if n == self.MAXNONCE:
            raise Exception('NoiseMaxNonceError: Nonce has depleted!')
        return self.cipher.decrypt(self._format_nonce(n), ciphertext, ad)

    def rekey(self, k: bytes):
        return self.encrypt(k, self.MAXNONCE, b'', b'\x00' * 32)[:32]


class BLAKE2s:
    """
    Implemented as per Noise Protocol specification - paragraph 4.3.
    """
    HASHLEN = 32
    BLOCKLEN = 64

    @classmethod
    def hash(cls, data: bytes) -> bytes:
        fn = partial(hashes.BLAKE2s, digest_size=cls.HASHLEN)
        h = hashes.Hash(fn(), default_backend())
        h.update(data)
        return h.finalize()

    @classmethod
    def _hmac_hash(cls, key: bytes, data: bytes) -> bytes:
        fn = partial(hashes.BLAKE2s, digest_size=cls.HASHLEN)
        h = hmac.HMAC(key, fn(), default_backend())
        h.update(data)
        return h.finalize()

    @classmethod
    def hkdf2(cls, chaining_key: bytes, input_key_material: bytes) -> Tuple[bytes, bytes]:
        temp_key = cls._hmac_hash(chaining_key, input_key_material)
        output1 = cls._hmac_hash(temp_key, b'\x01')
        output2 = cls._hmac_hash(temp_key, output1 + b'\x02')
        return output1, output2

    @classmethod
    def hkdf3(cls, chaining_key: bytes, input_key_material: bytes) -> Tuple[bytes, bytes, bytes]:
        temp_key = cls._hmac_hash(chaining_key, input_key_material)
        output1 = cls._hmac_hash(temp_key, b'\x01')
        output2 = cls._hmac_hash(temp_key, output1 + b'\x02')
        output3 = cls._hmac_hash(temp_key, output2 + b'\x03')
        return output1, output2, output3
