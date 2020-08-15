import logging
import socket
import select
from typing import Tuple, List, Optional
from timeit import default_timer
from time import sleep
import json
import collections
from . import packet, options, utils
from .exceptions import DHCPClientError


COL_LEN = 80

Lease = collections.namedtuple(
    "Lease", ["discover", "offer", "request", "ack", "time", "server"]
)


def format_dhcp_packet(pkt: packet.DHCPPacket) -> str:
    line_divider = ";-" + "".ljust(COL_LEN, "-") + ";\n"
    options_list = options.OptionList(pkt.options)
    msg_type_option = options_list.by_code(53)
    padding = " "
    if msg_type_option:
        msg_type = list(msg_type_option.value.values())[0]
    else:
        msg_type = "UNKNOWN MSG TYPE"
    broadcast = "BROADCAST" if pkt.flags else "UNICAST"
    client_info_padding = 18
    client_info = f"{pkt.htype} - {pkt.chaddr} ({utils.mac2vendor(pkt.chaddr)})"
    if (
        visual_diff := (
            utils.visual_length(client_info) - (COL_LEN - client_info_padding)
        )
    ) > 0:
        client_info = client_info[:-visual_diff]

    output = (
        f"{pkt.op} / {msg_type} / {broadcast}\n"
        + f"{len(pkt.asbytes)} bytes / TX ID {hex(pkt.xid).upper()} / {pkt.secs} seconds elapsed\n"
        + "Client info:".ljust(client_info_padding)
        + client_info
        + "\n"
        + "Client address:".ljust(client_info_padding)
        + f"{pkt.ciaddr}\n"
        + "Your address:".ljust(client_info_padding)
        + f"{pkt.yiaddr}\n"
        + "Next server:".ljust(client_info_padding)
        + f"{pkt.siaddr}\n"
        + "Relay:".ljust(client_info_padding)
        + f"{pkt.giaddr}"
    )

    output = (
        "\n".join(
            [
                f"; {line.ljust(COL_LEN if utils.visual_length(line) < COL_LEN else 0, padding)};"
                for line in output.split("\n")
            ]
        )
        + "\n"
    )
    output = line_divider + output + line_divider
    output += "; " + "OPTIONS:".ljust(COL_LEN, padding) + ";\n"
    output += (
        "\n".join(
            [
                f"; {line.ljust(COL_LEN, padding)};"
                for line in options_list.json.split("\n")
            ]
        )
        + "\n"
    )
    output += line_divider

    return output


class DHCPClient(object):
    def __init__(
        self,
        interface: str = None,
        send_from_port: int = 68,
        send_to_port: int = 67,
        max_retries: int = 10,
        socket_poll_interval: int = 10,
        retry_interval: int = 100,
    ):
        self.listening_ports = [67]
        self.send_from_port = send_from_port
        self.send_to_port = send_to_port
        self.max_pkt_size = 4096
        self.interface = interface
        self.listening_sockets = self.get_listening_sockets()
        self.writing_sockets = self.get_writing_sockets()
        self.listening_sockets += self.writing_sockets
        # self.listening_sockets += self.writing_sockets
        logging.debug(f"listening sockets: {self.listening_sockets}")
        logging.debug(f"write sockets: {self.writing_sockets}")
        self.except_sockets: List[socket.socket] = []
        self.max_tries = max_retries
        self.socket_poll_interval = socket_poll_interval
        self.retry_interval = retry_interval
        self.select_timout = 0
        self.offer_servers: List[str] = []
        self.ack_server: str = ""

    def send_discover(
        self, server: str, discover_packet: packet.DHCPPacket, verbosity: int
    ):
        self.send(server, self.send_to_port, discover_packet.asbytes, verbosity)

    def receive_offer(self, tx_id: int, verbosity: int) -> Optional[packet.DHCPPacket]:
        logging.debug("Listening for offer packet...")
        if verbosity > 1:
            print("Listening for OFFER packet")
        offer, addr = self.listen(tx_id, "DHCPOFFER", verbosity)
        if offer:
            logging.debug(f"Received offer packet from {addr} {offer}")
            if verbosity > 1:
                print(f"<< OFFER received from {addr[0]}:{addr[1]}")
                print(format_dhcp_packet(offer))
            self.offer_servers.append(addr)
        else:
            logging.debug("Did not receive offer, retrying")
            if verbosity > 1:
                print("Did not receive offer packet")
        return offer

    def send_request(
        self, server: str, request_packet: packet.DHCPPacket, verbosity: int
    ):
        self.send(server, self.send_to_port, request_packet.asbytes, verbosity)

    def receive_ack(self, tx_id: int, verbosity: int) -> Optional[packet.DHCPPacket]:
        logging.debug("Listening for ack packet...")
        if verbosity > 1:
            print("Listening for ACK packet")
        ack, addr = self.listen(tx_id, "DHCPACK", verbosity)
        if ack:
            logging.debug(f"Received ack packet from {addr} {ack}")
            if verbosity:
                print(f"<< ACK received from {addr[0]}:{addr[1]}")
                print(format_dhcp_packet(ack))
            self.ack_server = addr
        else:
            logging.debug("Did not receive ack, retrying")
            if verbosity > 1:
                print("Did not receive ack packet")
        return ack

    def get_lease(
        self,
        mac_addr: Optional[str] = None,
        broadcast: bool = True,
        relay: Optional[str] = None,
        server: str = "255.255.255.255",
        ip_protocol: int = 4,
        options_list: Optional[options.OptionList] = None,
        verbose: int = 0,
    ) -> Lease:
        mac_addr = mac_addr or utils.random_mac()
        logging.debug("Synthetizing discover packet")

        # D
        discover = packet.DHCPPacket.Discover(
            mac_addr, use_broadcast=broadcast, option_list=options_list, relay=relay
        )
        tx_id = discover.xid
        logging.debug(f"Constructed discover packet: {discover}")
        if verbose > 1:
            print(format_dhcp_packet(discover))
        start = default_timer()
        logging.debug(f"Sending discover packet to {server} with {tx_id=}")
        self.send_discover(server, discover, verbose)
        # O
        tries = 0
        while not (offer := self.receive_offer(tx_id, verbose)):
            logging.debug(f"Sleeping {self.retry_interval} ms then retrying discover")
            sleep(self.retry_interval / 1000)
            logging.debug(
                f"Attempt {tries} - Sending discover packet to {server} with {tx_id=}"
            )
            if verbose > 1:
                print("Resending DISCOVER packet")
            self.send_discover(server, discover, verbose)
            if tries > self.max_tries:
                raise DHCPClientError(
                    "Unable to obtain offer run client with -d for debug info"
                )
            tries += 1
        # R
        request = packet.DHCPPacket.Request(
            mac_addr,
            int(default_timer() - start),
            tx_id,
            use_broadcast=broadcast,
            option_list=options_list,
            client_ip=offer.yiaddr,
            relay=relay,
        )
        if verbose > 1:
            print("REQUEST Packet")
            print(format_dhcp_packet(request))
        logging.debug(f"Constructed request packet: {request}")
        logging.debug(f"Sending request packet to {server} with {tx_id=}")
        self.send_request(server, request, verbose)
        # A
        tries = 0
        while not (ack := self.receive_ack(tx_id, verbose)):
            logging.debug(f"Sleeping {self.retry_interval} ms then retrying request")
            sleep(self.retry_interval / 1000)
            logging.debug(
                f"Attempt {tries} - Sending request packet to {server} with {tx_id=}"
            )
            if verbose > 1:
                print("Resending REQUEST packet")
            self.send_request(server, request, verbose)
            if tries > self.max_tries:
                raise DHCPClientError(
                    "Unable to obtain ack run client with -d for debug info"
                )
            tries += 1

        lease_time = default_timer() - start
        lease = Lease(discover, offer, request, ack, lease_time, self.ack_server)

        if verbose:
            print(f"Client terminated after {lease_time * 1000:.0f} ms")
        else:
            print(
                f"Lease succesful: {ack.yiaddr} -- {ack.chaddr} -- {lease_time * 1000:.0f} ms elapsed"
            )
        return lease

    def get_valid_pkt(self, data: bytes) -> Optional[packet.DHCPPacket]:
        pkt = None
        try:
            pkt = packet.DHCPPacket.from_bytes(data)
        except Exception as e:
            logging.debug(
                f"Unable to parse received data as DHCP packet: {e} --- {data!r}"
            )
        return pkt

    def listen(
        self, tx_id: int, msg_type: str, verbosity: int
    ) -> Tuple[Optional[packet.DHCPPacket], Optional[str]]:
        logging.debug(
            f"Listening on {self.interface or 'all interfaces'}, UDP ports {self.listening_ports}"
        )
        tries = 0
        dhcp_packet, addr = None, None
        while tries < self.max_tries:
            logging.debug(
                f"Select: {select.select(self.listening_sockets, self.writing_sockets, self.except_sockets, 0)}"
            )
            if len(
                socks := select.select(
                    self.listening_sockets,
                    self.writing_sockets,
                    self.except_sockets,
                    self.select_timout,
                )[0]
            ):
                for sock in socks:
                    data, addr = sock.recvfrom(self.max_pkt_size)
                    logging.debug(f"Received data from {addr}: {data}")
                    if (
                        (dhcp_packet := self.get_valid_pkt(data)) is not None
                        and dhcp_packet.xid == tx_id
                        and dhcp_packet.msg_type == msg_type
                    ):
                        logging.debug(
                            f"Received valid DHCP packet of {dhcp_packet.msg_type} type"
                        )
                        return dhcp_packet, addr
                    else:
                        if dhcp_packet is None:
                            logging.debug("Invalid DHCP packet")
                        elif dhcp_packet.xid != tx_id:
                            logging.debug(
                                f"TX ID does not match expected ID {dhcp_packet.xid} != {tx_id}"
                            )
                        elif (msg_type_actual := dhcp_packet.msg_type) != msg_type:
                            logging.debug(
                                f"DHCP message type does not match expected: {msg_type_actual} != {msg_type}"
                            )
                        else:
                            logging.debug("Something is wrong with this packet")
                        logging.debug(dhcp_packet)
                        dhcp_packet = None
                        tries += 1
            else:
                logging.debug(
                    f"Attempt {tries} - No sockets available to read from... "
                    f"sleeping for {self.socket_poll_interval} ms"
                )
                if verbosity > 2:
                    print("Did not receive packet, sleeping...")
                tries += 1
                sleep(self.socket_poll_interval / 1000)
        return dhcp_packet, addr

    def get_socket(self, host: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setblocking(False)
        if self.interface:
            try:
                # Option 25 is SO_BINDTODEVICE, allows us to specify a device
                # to bind to with this socket
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())
                logging.info(f"Binding to {self.interface}")
            except:
                # Less reliable method of binding to interface, required where
                # socket option 25 does not exist (Windows)
                sock.bind((utils.get_ip_by_iface(self.interface), port))
            else:
                sock.bind((host, port))
        else:
            sock.bind((host, port))

        logging.info(f"Bound {socket}")
        return sock

    def get_writing_sockets(self) -> List[socket.socket]:
        host = ""
        port = self.send_from_port
        logging.debug(f"Creating socket to send data, binding to {(host, port)}")
        client_sock = self.get_socket(host, port)
        return [client_sock]

    def get_listening_sockets(self) -> List[socket.socket]:
        socks = []
        host = ""
        for port in self.listening_ports:
            logging.debug(f"Creating socket to receiving data, binding to {(host, port)}")
            server_sock = self.get_socket(host, port)
            socks.append(server_sock)
        return socks

    def send(self, remote_addr: str, remote_port: int, data: bytes, verbosity: int):
        tries = 0
        while tries < self.max_tries:
            logging.debug(f"Select: {select.select(self.listening_sockets, self.writing_sockets, self.except_sockets, self.select_timout,)}")
            if len(
                socks := select.select(
                    self.listening_sockets,
                    self.writing_sockets,
                    self.except_sockets,
                    self.select_timout,
                )[1]
            ):
                sock = socks[0]
                logging.debug(f"Connecting to {remote_addr}:{remote_port}")
                logging.debug(f"Sending data {data!r}")
                if verbosity > 1:
                    print(f">> Sending packet {remote_addr}:{remote_port}")
                sock.sendto(data, (remote_addr, remote_port))
                logging.debug(f"Packet Sent")
                break
            else:
                logging.warning(
                    f"Attempt {tries} - No sockets available to write to... "
                    f"sleeping for {self.socket_poll_interval} ms"
                )
                tries += 1
                sleep(self.socket_poll_interval / 1000)
