import socket
import enum
import logging
import struct
import Packets

class GDBPacketInvalidChecksumError(Exception):
    pass

class GDBPacketInvalidPacketError(Exception):
    pass

class GDBServerNetworkError(Exception):
    pass



class GDBClientHandler:
    def __init__(self, socket, vendor, logger):
        self._socket = socket
        self._vendor = vendor
        self._logger = logger
        self._logger.debug("GDBClientHandler created")
        self._last_sent_packet = None
        self._packet_type_handlers = {
            Packets.GDBPacketType.REGULAR_PACKET: self._handle_regular_packet,
            Packets.GDBPacketType.ACK: lambda nop: None,
            Packets.GDBPacketType.RETRANSMIT: lambda packet: self.retransmit() # Lambda since handlers give 'packet' and we want to ignore it here
        }
        self._packet_handlers = {
            # '!': vendor.handle_extended_mode,
            # '?': vendor.handle_question_mark,
        }

    @classmethod
    def calculate_packet_checksum(cls, packet_bytes):
        checksum = 0
        for byte in packet_bytes:
            checksum += byte
        return checksum & 0xff
    
    @classmethod
    def escape_packet_byte(cls, byte):
        return byte ^ 0x20

    def close(self):
        self._socket.close()
        self._vendor.fini()
        self._logger.debug("GDBClientHandler closed")
        self._is_running = False

    def run(self):
        self._is_running = True
        self._logger.debug("Running loop")
        while self._is_running:
            try:
                self._handle(self.receive())
            except (GDBPacketInvalidChecksumError, GDBPacketInvalidPacketError) as e:
                self._send_packet_failure()

    def _send_packet_ack(self):
        self._socket.send(Packets.GDBPacketConsts.PACKET_ACK)

    def _send_packet_failure(self):
        self._socket.send(Packets.GDBPacketConsts.PACKET_RETRANSMIT)

    def _handle_regular_packet(self, packet):
        command_type = packet.command
        if command_type in self._packet_handlers:
            self._packet_handlers[command_type](packet)
        else:
            self._logger.info(
                "No handler for packet command {}, packet data was: {}\nSending unsupported to client"
                .format(
                    packet.command,
                    packet.data
                )
            )
            # TODO: Return unsupported

    def _handle(self, packet):
        self._logger.info("Recieved packet:\n{}\n".format(packet))
        self._send_packet_ack() # Each recv'd packet must be acked
        if packet.type in self._packet_type_handlers:
            self._packet_type_handlers[packet.type](packet)
        else:
            self._logger.info("No handler for packet type {}, packet data was: {}".format(packet.type, packet.data))

    def _handle_extended_mode(self, packet_data):
        pass

    def _handle_packet_data_recv(self):
        """
        This function will handle the recv of packet data, and only packet data.
        This function expects the socket buffer to NOT contain PACKET_START.
        This function WILL handle the validation of the checksum.
        :raises: GDBPacketInvalidChecksumError
        :returns: packet_data as bytes
        """
        packet_data = b''
        current_char = b''

        # Recv until end
        while current_char != Packets.GDBPacketConsts.PACKET_END:
            packet_data = packet_data + current_char
            current_char = self._socket.recv(1)
            # When an escape character shows, the next byte should be escaped
            # Due to the fact that escape chars can be '#' we have to immediatly add them
            if current_char == Packets.GDBPacketConsts.PACKET_ESCAPE:
                packet_data = packet_data + self.escape_packet_byte(self._socket.recv(1))
                # Get the next byte for the next iteration
                current_char = self._socket.recv(1)

        # Reached End of Packet, last 2 bytes should be checksum
        reported_packet_checksum = self._socket.recv(2)
        calculated_packet_checksum = self.calculate_packet_checksum(packet_data)
        if reported_packet_checksum != calculated_packet_checksum:
            raise GDBPacketInvalidChecksumError

        self._logger.debug("Recv'd packet (valid checksum):\n{}\n".format(packet_data))
        return packet_data

    def receive(self):
        """
        Recieve incoming packets from a GDB client from the socket.
        :returns: GDBClientPacket
        :raises: GDBPacketInvalidPacketError, GDBPacketInvalidChecksumError (Due to _handle_packet_data_recv)
        """

        packet_data = ''
        packet_type = self._socket.recv(1)
        self._logger.debug("First char is : {}\n".format(packet_type))
        if len(packet_type) < 1:
            self._logger.info("Client dropped")
            self.close()

        try:
            packet_type_enum = Packets.GDBPacketType(packet_type)
            if packet_type_enum == Packets.GDBPacketType.REGULAR_PACKET: # If its a regular packet, get packet data
                packet = Packets.GDBClientPacket(packet_type_enum, self._handle_packet_data_recv())
            else:
                packet = Packets.GDBClientPacket(packet_type_enum)

            return packet
        except ValueError:
            self._logger.error("Invalid packet type '{}'".format(packet_type))
            raise GDBPacketInvalidPacketError

    def _send_raw_msg(self, raw_bytes):
        """
        Sends a raw message.
        DO NOT USE unless necessary.
        Cases where it should be used:
            - Sending a GDB Packet that has been assembled
            - Sending simple packets (packet ack / packet invalid)
            - Retransmit
        :param raw_bytes: bytes to send
        """

        self._socket.send(raw_bytes)

    def retransmit(self):
        if self._last_sent_packet != None:
            self._send_raw_msg(self._last_sent_packet)
        else:
            self._logger.error("Retransmit asked when no packets were sent.")

    def send_data(self, data):
        """
        Construct a GDB packet and send it
        :param data: data to send
        """

        self._logger.info("Sending:\n{}\n".format(data))
        # Encode since send requires bytes
        packet = "$%s#%.2x" % (data, self.calculate_packet_checksum(data)).encode()
        self._send_raw_msg(packet)
        self._last_sent_packet = packet # Save the packet in case of re-transmit


class GDBClientHandlerlegacy(object):
    def __init__(self, clientsocket):
        self.clientsocket = clientsocket
        self.netin = clientsocket.makefile('r')
        self.netout = clientsocket.makefile('w')
        self.log = logging.getLogger('gdbclienthandler')
        self.last_pkt = None

    def close(self):
        '''End of story!'''
        self.netin.close()
        self.netout.close()
        self.clientsocket.close()
        self.log.info('closed')

    def run(self):
        '''Some doc about the available commands here:
            * http://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html#id3081722
            * http://git.qemu.org/?p=qemu.git;a=blob_plain;f=gdbstub.c;h=2b7f22b2d2b8c70af89954294fa069ebf23a5c54;hb=HEAD +
             http://git.qemu.org/?p=qemu.git;a=blob_plain;f=target-i386/gdbstub.c;hb=HEAD'''
        self.log.info('client loop ready...')
        while self.receive() == 'Good':
            pkt = self.last_pkt
            self.log.debug('receive(%r)' % pkt)
            # Each packet should be acknowledged with a single character. '+' to indicate satisfactory receipt
            self.send_raw('+')

            def handle_q(subcmd):
                '''
                subcmd Supported: https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html#qSupported
                Report the features supported by the RSP server. As a minimum, just the packet size can be reported.
                '''
                if subcmd.startswith('Supported'):
                    self.log.info('Received qSupported command')
                    self.send('PacketSize=%x' % 4096)
                elif subcmd.startswith('Attached'):
                    self.log.info('Received qAttached command')
                    # https://sourceware.org/gdb/onlinedocs/gdb/General-Query-Packets.html
                    self.send('0')
                elif subcmd.startswith('C'):
                    self.send('T%.2x;' % GetCpuThreadId())
                else:
                    self.log.error('This subcommand %r is not implemented in q' % subcmd)
                    self.send('')

            def handle_h(subcmd):
                self.send('OK')

            def handle_qmark(subcmd):
                self.send('S%.2x' % GDB_SIGNAL_TRAP)

            def handle_g(subcmd):
                if subcmd == '':
                    # EAX, ECX, EDX, ESP, EBP, ESI, EDI, EIP, EFLAGS, CS, SS, DS, ES, FS, GS
                    registers = [
                        GetEax(), GetEcx(), GetEdx(), GetEbx(), GetEsp(),
                        GetEbp(), GetEsi(), GetEdi(), GetEip(), GetEflags(),
                        GetCs(), GetSs(), GetDs(), GetEs(), GetFs(), GetGs()
                    ]
                    s = ''
                    for r in registers:
                        s += struct.pack('<I', r).encode('hex')
                    self.send(s)

            def handle_m(subcmd):
                addr, size = subcmd.split(',')
                addr = int(addr, 16)
                size = int(size, 16)
                self.log.info('Received a "read memory" command (@%#.8x : %d bytes)' % (addr, size))
                self.send(ReadMemory(size, addr).encode('hex'))

            def handle_s(subcmd):
                self.log.info('Received a "single step" command')
                StepInto()
                self.send('T%.2x' % GDB_SIGNAL_TRAP)

            dispatchers = {
                'q' : handle_q,
                'H' : handle_h,
                '?' : handle_qmark,
                'g' : handle_g,
                'm' : handle_m,
                's' : handle_s
            }

            cmd, subcmd = pkt[0], pkt[1 :]
            if cmd == 'k':
                break

            if cmd not in dispatchers:
                self.log.info('%r command not handled' % pkt)
                self.send('')
                continue

            dispatchers[cmd](subcmd)

        self.close()

    def send(self, msg):
        '''Send a packet to the GDB client'''
        self.log.debug('send(%r)' % msg)
        self.send_raw('$%s#%.2x' % (msg, checksum(msg)))

    def send_raw(self, r):
        self.netout.write(r)
        self.netout.flush()     

def main():
    logging.basicConfig(level = logging.DEBUG)
    GDBClientHandler(socket.create_server(("", 1337)).accept()[0], None, logging).run()
    for logger in 'gdbclienthandler runner main'.split(' '):
        logging.getLogger(logger).setLevel(level = logging.INFO)

    log = logging.getLogger('main')
    port = 31337
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    log.info('listening on :%d' % port)
    sock.listen(1)
    conn, addr = sock.accept()
    log.info('connected')

    GDBClientHandler(conn).run()
    return 1

if __name__ == '__main__':
    main()