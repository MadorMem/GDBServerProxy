import enum

class GDBCommandType(enum.Enum):
    pass

class GDBPacketType(enum.Enum):
    ACK = b'+'
    RETRANSMIT = b'-'
    REGULAR_PACKET = b'$'
    BREAK = b'\x03'
    DISCONNECT = b''

class GDBPacketConsts:
    PACKET_ACK = b'+'
    PACKET_RETRANSMIT = b'-'
    PACKET_END = b'#'
    PACKET_ESCAPE = b'}'

class GDBClientPacket:
    """
    This class represents a packet sent by a GDB Client connected to the GDB Server
    """
    END_OF_PACKET = '#'
    START_OF_PACKET = '$'

    def __init__(self, packet_type, raw_packet_data=None, **kwargs):
        self._type = packet_type
        self._command = None
        self._raw_data = raw_packet_data
        self.__dict__.update(kwargs) # This will add any variable name to the class given as a kwargs

    @property
    def type(self):
        return self._type

    @property
    def command(self):
        return self._command

    @property
    def data(self):
        return self._data