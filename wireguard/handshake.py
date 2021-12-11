
import os
import base64
import datetime
import struct
from hashlib import blake2s

from .message import Initiation, Response, TYPE_HANDSHAKE_INITIATION, TYPE_HANDSHAKE_RESPONSE
from noise_ikpsk2_25519_chachapoly_blake2s.connection import Connection


WG_IDENTIFIER   = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
WG_LABEL_MAC1   = b"mac1----"
WG_LABEL_COOKIE = b"cookie--"
DEFAULT_EPOCH   = 4611686018427387914  # 1972-01-01 for TAI dates


class Initiator:
    def __init__(self, our_private: str, their_public: str, psk: str=None):
        self.our_private = our_private
        self.their_public = their_public
        self.psk = psk
        self.remote_id = b''
        self.init_msg = Initiation()
        self.resp_msg = Response()

        self.noise = Connection(
            initiator       = True,
            prologue        = WG_IDENTIFIER,
            our_private     = base64.b64decode(our_private),
            their_public    = base64.b64decode(their_public),
            psk             = base64.b64decode(psk) if psk else None,
        )

    def send(self) -> bytes:
        msg = self.init_msg
        msg.type = TYPE_HANDSHAKE_INITIATION
        msg.sender = os.urandom(4)

        now = datetime.datetime.now()
        tai = struct.pack('!qi', DEFAULT_EPOCH + int(now.timestamp()), int(now.microsecond * 1e3))
        payload = self.noise.handshake_write(tai)
        msg.ephemeral, msg.static, msg.timestamp = payload[0:32], payload[32:80], payload[80:108]

        mac_key = blake2s(WG_LABEL_MAC1 + base64.b64decode(self.their_public)).digest()
        msg.mac1 = blake2s(
            b''.join((msg.type, msg.reserved, msg.sender, msg.ephemeral, msg.static, msg.timestamp)),
            digest_size=16, key=mac_key).digest()

        print(msg)
        return msg.to_network()

    def recv(self, packet: bytes):
        assert len(packet) >= Response.MESSAGE_SIZE, f"insufficient response packet length: {len(packet)}"

        msg = self.resp_msg
        msg.from_network(packet[:Response.MESSAGE_SIZE])
        empty = self.noise.handshake_read(msg.ephemeral + msg.empty)
        self.remote_id = msg.sender
        print(msg)

        assert msg.type     == TYPE_HANDSHAKE_RESPONSE, "invalid message type"
        assert msg.reserved == b'\x00' * 3,             "invalid reserved"
        assert msg.receiver == self.init_msg.sender,    "invalid receiver"
        assert empty        == b'',                     "invalid empty"


class Responder:
    def __init__(self, our_private: str, their_public: str, psk: str=None):
        self.our_private = our_private
        self.their_public = their_public
        self.psk = psk
        self.remote_id = b''
        self.init_msg = Initiation()
        self.resp_msg = Response()

        self.noise = Connection(
            initiator       = False,
            prologue        = WG_IDENTIFIER,
            our_private     = base64.b64decode(our_private),
            their_public    = base64.b64decode(their_public),
            psk             = base64.b64decode(psk) if psk else None,
        )

    def recv(self, packet: bytes):
        assert len(packet) >= Initiation.MESSAGE_SIZE, f"insufficient response packet length: {len(packet)}"

        msg = self.init_msg
        msg.from_network(packet[:Initiation.MESSAGE_SIZE])
        _empty = self.noise.handshake_read(msg.ephemeral + msg.static + msg.timestamp)
        self.remote_id = msg.sender
        print(msg)

        assert msg.type     == TYPE_HANDSHAKE_INITIATION, "invalid message type"
        assert msg.reserved == b'\x00' * 3,             "invalid reserved"

    def send(self) -> bytes:
        msg = self.resp_msg
        msg.type = TYPE_HANDSHAKE_RESPONSE
        msg.sender = os.urandom(4)
        msg.receiver = self.init_msg.sender

        payload = self.noise.handshake_write(b'')
        msg.ephemeral, msg.empty = payload[0:32], payload[32:48]

        mac_key = blake2s(WG_LABEL_MAC1 + base64.b64decode(self.their_public)).digest()
        msg.mac1 = blake2s(
            b''.join((msg.type, msg.reserved, msg.sender, msg.receiver, msg.ephemeral, msg.empty)),
            digest_size=16, key=mac_key).digest()

        print(msg)
        return msg.to_network()

