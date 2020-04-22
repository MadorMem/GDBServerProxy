class GDBClientPacket:
    """
    This class represents a packet sent by a GDB Client connected to the GDB Server
    """
    END_OF_PACKET = '#'
    START_OF_PACKET = '$'

    def __init__(self, command_type, data, **kwargs):
        self._type = command_type
        self._data = data
        self.__dict__.update(kwargs) # This will add any variable name to the class given as a kwargs

    @property
    def type(self):
        return self._type

    @property
    def data(self):
        return self._data