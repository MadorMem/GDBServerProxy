class GDBClientPacket:
    """
    This class represents a packet sent by a GDB Client connected to the GDB Server
    """

    def __init__(self, packet_type, args):
        self._type = packet_type
        self.args = args

    @property
    def type(self):
        return self._type

    @property
    def args(self):
        return self._type