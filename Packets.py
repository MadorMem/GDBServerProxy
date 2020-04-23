import enum

class GDBCommandType(enum.Enum):
    pass

class GDBPacketType(enum.Enum):
    BREAK = 0
    REGULAR_PACKET = 1
    RETRANSMIT = 2
    ACK = 3
    DISCONNECT = 4

class GDBPacketConsts:
    PACKET_START = b'$'
    PACKET_END = b'#'
    PACKET_ESCAPE = b'}'
    PACKET_ACK = b'+'
    PACKET_FAILURE = b'-'

class GDBClientPacket:
    """
    This class represents a packet sent by a GDB Client connected to the GDB Server
    """
    END_OF_PACKET = '#'
    START_OF_PACKET = '$'

    def __init__(self, packet_type, command_type=None, data=None, **kwargs):
        self._type = packet_type
        self._command = command_type
        self._data = data
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