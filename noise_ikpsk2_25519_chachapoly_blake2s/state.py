
from typing import Optional, Tuple
from .crypto import KeyPair25519, ED25519, ChaChaPoly, BLAKE2s

PROTOCOL_NAME = b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'

TOKEN_E = 'e'
TOKEN_S = 's'
TOKEN_EE = 'ee'
TOKEN_ES = 'es'
TOKEN_SE = 'se'
TOKEN_SS = 'ss'
TOKEN_PSK = 'psk'

# Handshake pattern of initiator and responder
PATTERN_I = [TOKEN_E, TOKEN_ES, TOKEN_S, TOKEN_SS]
PATTERN_R = [TOKEN_E, TOKEN_EE, TOKEN_SE, TOKEN_PSK]


class CipherState:
    """
    Implemented as per Noise Protocol specification - paragraph 5.1.
    """
    def __init__(self, k: bytes):
        self.k = k
        self.n = 0
        self.cipher = ChaChaPoly(self.k)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        ciphertext = self.cipher.encrypt(self.k, self.n, ad, plaintext)
        self.n = self.n + 1
        return ciphertext

    def decrypt_with_ad(self, ad: bytes, ciphertext: bytes) -> bytes:
        plaintext = self.cipher.decrypt(self.k, self.n, ad, ciphertext)
        self.n = self.n + 1
        return plaintext

    def rekey(self):
        self.k = self.cipher.rekey(self.k)
        self.cipher = ChaChaPoly(self.k)


class SymmetricState:
    """
    Implemented as per Noise Protocol specification - paragraph 5.2.
    """
    def __init__(self):
        self.h = BLAKE2s.hash(PROTOCOL_NAME)
        self.ck = self.h
        self.cipher_state: CipherState = None

    def mix_key(self, input_key_material: bytes):
        self.ck, temp_k = BLAKE2s.hkdf2(self.ck, input_key_material)
        self.cipher_state = CipherState(temp_k)

    def mix_hash(self, data: bytes):
        self.h = BLAKE2s.hash(self.h + data)

    def mix_key_and_hash(self, input_key_material: bytes):
        self.ck, temp_h, temp_k = BLAKE2s.hkdf3(self.ck, input_key_material)
        self.mix_hash(temp_h)
        self.cipher_state = CipherState(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """
        Sets ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
        """
        ciphertext = self.cipher_state.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """
        Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext.
        """
        plaintext = self.cipher_state.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        """
        Returns a pair of CipherState objects for encrypting/decrypting transport messages.
        """
        temp_k1, temp_k2 = BLAKE2s.hkdf2(self.ck, b'')
        return CipherState(temp_k1), CipherState(temp_k2)


class HandshakeState:
    """
    Implemented as per Noise Protocol specification - paragraph 5.3.
    """
    def __init__(self, initiator: bool, prologue: bytes, our_private: bytes, their_public: bytes, psk: bytes=None):
        self.initiator = initiator
        self.psk = psk

        self.s = KeyPair25519.from_private(our_private)
        self.e: KeyPair25519 = None
        self.rs = KeyPair25519.from_public(their_public)
        self.re: KeyPair25519 = None

        self.symmetric_state = SymmetricState()

        self.symmetric_state.mix_hash(prologue)
        keypair = self.rs if initiator else self.s
        self.symmetric_state.mix_hash(keypair.public_bytes)

    def write_message(self, payload: bytes, message_buffer: bytearray) -> Tuple[Optional[CipherState], Optional[CipherState]]:
        """
        Comments below are mostly copied from specification.
        """
        message_pattern = PATTERN_I if self.initiator else PATTERN_R

        for token in message_pattern:
            if token == TOKEN_E:
                # Sets e = GENERATE_KEYPAIR(). Appends e.public_key to the buffer. Calls MixHash(e.public_key)
                if not self.e:
                    self.e = ED25519.generate_keypair()
                message_buffer += self.e.public_bytes
                self.symmetric_state.mix_hash(self.e.public_bytes)
                if self.psk:
                    self.symmetric_state.mix_key(self.e.public_bytes)

            elif token == TOKEN_S:
                # Appends EncryptAndHash(s.public_key) to the buffer
                message_buffer += self.symmetric_state.encrypt_and_hash(self.s.public_bytes)

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re))
                self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.re.public))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.rs.public))
                else:
                    self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.re.public))

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.re.public))
                else:
                    self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.rs.public))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.rs.public))

            elif token == TOKEN_PSK:
                self.symmetric_state.mix_key_and_hash(self.psk)

            else:
                raise NotImplementedError('Pattern token: {}'.format(token))

        # Appends EncryptAndHash(payload) to the buffer
        message_buffer += self.symmetric_state.encrypt_and_hash(payload)

        if self.initiator:
            return None, None

        c1, c2 = self.symmetric_state.split()
        return c2, c1

    def read_message(self, message: bytes, payload_buffer: bytearray) -> Tuple[Optional[CipherState], Optional[CipherState]]:
        """
        Comments below are mostly copied from specification.
        """
        message_pattern = PATTERN_R if self.initiator else PATTERN_I

        for token in message_pattern:
            if token == TOKEN_E:
                # Sets re to the next DHLEN bytes from the message. Calls MixHash(re.public_key).
                self.re = KeyPair25519.from_public(bytes(message[:ED25519.DHLEN]))
                message = message[ED25519.DHLEN:]
                self.symmetric_state.mix_hash(self.re.public_bytes)
                if self.psk:
                    self.symmetric_state.mix_key(self.re.public_bytes)

            elif token == TOKEN_S:
                # Sets temp to the next DHLEN + 16 bytes of the message if HasKey() == True, or to the next DHLEN bytes
                # otherwise. Sets rs to DecryptAndHash(temp).
                if self.symmetric_state.cipher_state.k:
                    temp = bytes(message[:ED25519.DHLEN + 16])
                    message = message[ED25519.DHLEN + 16:]
                else:
                    temp = bytes(message[:ED25519.DHLEN])
                    message = message[ED25519.DHLEN:]
                self.rs = KeyPair25519.from_public(self.symmetric_state.decrypt_and_hash(temp))

            elif token == TOKEN_EE:
                # Calls MixKey(DH(e, re)).
                self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.re.public))

            elif token == TOKEN_ES:
                # Calls MixKey(DH(e, rs)) if initiator, MixKey(DH(s, re)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.rs.public))
                else:
                    self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.re.public))

            elif token == TOKEN_SE:
                # Calls MixKey(DH(s, re)) if initiator, MixKey(DH(e, rs)) if responder
                if self.initiator:
                    self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.re.public))
                else:
                    self.symmetric_state.mix_key(ED25519.dh(self.e.private, self.rs.public))

            elif token == TOKEN_SS:
                # Calls MixKey(DH(s, rs))
                self.symmetric_state.mix_key(ED25519.dh(self.s.private, self.rs.public))

            elif token == TOKEN_PSK:
                self.symmetric_state.mix_key_and_hash(self.psk)

            else:
                raise NotImplementedError('Pattern token: {}'.format(token))

        # Calls DecryptAndHash() on the remaining bytes of the message and stores the output into payload_buffer.
        payload_buffer += self.symmetric_state.decrypt_and_hash(bytes(message))

        if self.initiator:
            return self.symmetric_state.split()

        return None, None

