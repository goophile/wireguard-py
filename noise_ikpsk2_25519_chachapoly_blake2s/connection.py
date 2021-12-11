
from .state import HandshakeState, CipherState


class Connection:
    def __init__(self, initiator: bool, prologue: bytes, our_private: bytes, their_public: bytes, psk: bytes=None):
        self.initiator = initiator
        self.handshake_state = HandshakeState(initiator, prologue, our_private, their_public, psk)
        self.cipher_state_encrypt: CipherState = None
        self.cipher_state_decrypt: CipherState = None

    def handshake_write(self, payload: bytes) -> bytes:
        message_buffer = bytearray()
        c1, c2 = self.handshake_state.write_message(payload, message_buffer)
        # if self.initiator = False
        if c1 and c2:
            self.cipher_state_encrypt = c1
            self.cipher_state_decrypt = c2
        return bytes(message_buffer)

    def handshake_read(self, message: bytes) -> bytes:
        payload_buffer = bytearray()
        c1, c2 = self.handshake_state.read_message(message, payload_buffer)
        # if self.initiator = True
        if c1 and c2:
            self.cipher_state_encrypt = c1
            self.cipher_state_decrypt = c2
        return bytes(payload_buffer)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher_state_encrypt.encrypt_with_ad(None, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher_state_decrypt.decrypt_with_ad(None, ciphertext)

    def rekey_inbound_cipher(self):
        self.cipher_state_decrypt.rekey()

    def rekey_outbound_cipher(self):
        self.cipher_state_encrypt.rekey()
