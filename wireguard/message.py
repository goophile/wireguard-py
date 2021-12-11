
from collections import OrderedDict

TYPE_HANDSHAKE_INITIATION = b'\x01'
TYPE_HANDSHAKE_RESPONSE   = b'\x02'
TYPE_TRANSPORT_DATA       = b'\x04'


class Initiation:
    MESSAGE_SIZE = 148
    FIELD_SIZE = OrderedDict([
        ('type'      , 1 ),
        ('reserved'  , 3 ),
        ('sender'    , 4 ),
        ('ephemeral' , 32),
        ('static'    , 48),
        ('timestamp' , 28),
        ('mac1'      , 16),
        ('mac2'      , 16),
    ])

    def __init__(self):
        self.type       = b'\x00' * 1
        self.reserved   = b'\x00' * 3
        self.sender     = b'\x00' * 4
        self.ephemeral  = b'\x00' * 32
        self.static     = b'\x00' * 48  # Encrypted Static
        self.timestamp  = b'\x00' * 28  # Encrypted Timestamp
        self.mac1       = b'\x00' * 16
        self.mac2       = b'\x00' * 16

    def __repr__(self) -> str:
        result = '\n'
        for field in self.FIELD_SIZE.keys():
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value.hex()}\n'
        return result

    def to_network(self) -> bytes:
        for field, size in self.FIELD_SIZE.items():
            assert len(getattr(self, field)) == size, f"invalid size for field: {field}"
        return b''.join((self.type, self.reserved, self.sender, self.ephemeral, self.static, self.timestamp, self.mac1, self.mac2))

    def from_network(self, data: bytes):
        assert len(data) == self.MESSAGE_SIZE, f"invalid incoming message size: {len(data)}"
        (
            self.type, self.reserved, self.sender, self.ephemeral, self.static, self.timestamp, self.mac1, self.mac2
        ) = (
            data[0   : 1   ],
            data[1   : 4   ],
            data[4   : 8   ],
            data[8   : 40  ],
            data[40  : 88  ],
            data[88  : 116 ],
            data[116 : 132 ],
            data[132 : 148 ],
        )


class Response:
    MESSAGE_SIZE = 92
    FIELD_SIZE = OrderedDict([
        ('type'      , 1 ),
        ('reserved'  , 3 ),
        ('sender'    , 4 ),
        ('receiver'  , 4 ),
        ('ephemeral' , 32),
        ('empty'     , 16),
        ('mac1'      , 16),
        ('mac2'      , 16),
    ])

    def __init__(self):
        self.type       = b'\x00' * 1
        self.reserved   = b'\x00' * 3
        self.sender     = b'\x00' * 4
        self.receiver   = b'\x00' * 4
        self.ephemeral  = b'\x00' * 32
        self.empty      = b'\x00' * 16  # Encrypted Empty
        self.mac1       = b'\x00' * 16
        self.mac2       = b'\x00' * 16

    def __repr__(self) -> str:
        result = '\n'
        for field in self.FIELD_SIZE.keys():
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value.hex()}\n'
        return result

    def to_network(self) -> bytes:
        for field, size in self.FIELD_SIZE.items():
            assert len(getattr(self, field)) == size, f"invalid size for field: {field}"
        return b''.join((self.type, self.reserved, self.sender, self.receiver, self.ephemeral, self.empty, self.mac1, self.mac2))

    def from_network(self, data: bytes):
        assert len(data) == self.MESSAGE_SIZE, f"invalid incoming message size: {len(data)}"
        (
            self.type, self.reserved, self.sender, self.receiver, self.ephemeral, self.empty, self.mac1, self.mac2
        ) = (
            data[0   : 1   ],
            data[1   : 4   ],
            data[4   : 8   ],
            data[8   : 12  ],
            data[12  : 44  ],
            data[44  : 60  ],
            data[60  : 76  ],
            data[76  : 92  ],
        )


class DataHeader:
    HEADER_SIZE = 16
    FIELD_SIZE = OrderedDict([
        ('type'      , 1 ),
        ('reserved'  , 3 ),
        ('receiver'  , 4 ),
        ('counter'   , 8 ),
    ])

    def __init__(self):
        self.type       = b'\x00' * 1
        self.reserved   = b'\x00' * 3
        self.receiver   = b'\x00' * 4
        self.counter    = b'\x00' * 8

    def __repr__(self) -> str:
        result = '\n'
        for field in self.FIELD_SIZE.keys():
            value = getattr(self, field)
            result += f'{field.ljust(12)}: {value.hex()}\n'
        return result

    def to_network(self) -> bytes:
        for field, size in self.FIELD_SIZE.items():
            assert len(getattr(self, field)) == size, f"invalid size for field: {field}"
        return b''.join((self.type, self.reserved, self.receiver, self.counter))

    def from_network(self, data: bytes):
        assert len(data) == self.HEADER_SIZE, f"invalid incoming message size: {len(data)}"
        (
            self.type, self.reserved, self.receiver, self.counter
        ) = (
            data[0   : 1   ],
            data[1   : 4   ],
            data[4   : 8   ],
            data[8   : 16  ],
        )
