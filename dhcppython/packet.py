import struct
import ipaddress
import random
from dataclasses import dataclass
from typing import ClassVar, List, Dict, Union, Optional
from . import options, utils
from .exceptions import MalformedPacketError, DHCPValueError


OPTIONS_INTERFACE = options.options


@dataclass
class DHCPPacket(object):
    """
    This class models a DHCP packet. From RFC 2131:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
    +---------------+---------------+---------------+---------------+
    |                            xid (4)                            |
    +-------------------------------+-------------------------------+
    |           secs (2)            |           flags (2)           |
    +-------------------------------+-------------------------------+
    |                          ciaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          yiaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          siaddr  (4)                          |
    +---------------------------------------------------------------+
    |                          giaddr  (4)                          |
    +---------------------------------------------------------------+
    |                                                               |
    |                          chaddr  (16)                         |
    |                                                               |
    |                                                               |
    +---------------------------------------------------------------+
    |                                                               |
    |                          sname   (64)                         |
    +---------------------------------------------------------------+
    |                                                               |
    |                          file    (128)                        |
    +---------------------------------------------------------------+
    |                                                               |
    |                          options (variable)                   |
    +---------------------------------------------------------------+
    """

    op: str  # 1 octet - Message Type: 1 is a BOOTREQUEST, 2 is a BOOTREPLY
    htype: str  # 1 octet - Hardware Type: 1 for 10mb ethernet
    hlen: int  # 1 octet - Hardware Address Length: 6 for 10mb ethernet
    hops: int  # 1 octet - Hops: clients should set this to 0, may be used by relay
    xid: int  # 4 octets - Transaction ID: random number, maintained for entire tx
    secs: int  # 2 octets - Seconds: number of seconds since addr process began
    flags: int  # 2 octets - Flags: bits 1-15 reserved, bit 0 indicates whether to use broadcast
    ciaddr: ipaddress.IPv4Address  # 4 octets - Client Address: filled in if client can respond to ARP
    yiaddr: ipaddress.IPv4Address  # 4 octets - 'your' (client) IP address
    siaddr: ipaddress.IPv4Address  # 4 octets - Next Server: IP of next server to use for bootstrap (OFFER/ACK)
    giaddr: ipaddress.IPv4Address  # 4 octets - Relay Agent: relay IP
    chaddr: str  # 16 octets - Client Hardware Addr: MAC addr of client (usually len 6 + 10 padding)
    sname: bytes  # 64 octets - Server Name: optional, host name, null terminated
    file: bytes  # 128 octets - File Name: Null terminated str, boot file name
    options: options.OptionList  # N octets - Options Field: variable length, options section started by the DHCP
    magic_cookie: ClassVar[bytes] = b"\x63\x82\x53\x63"
    cookie_offset_start: ClassVar[int] = 236
    cookie_offset_end: ClassVar[int] = 240
    packet_fmt: ClassVar[str] = "!BBBBLHHLLLL16s64s128s"
    op_map: ClassVar[Dict[int, str]] = {1: "BOOTREQUEST", 2: "BOOTREPLY"}
    inverse_op_map: ClassVar[Dict[str, int]] = {v: k for k, v in op_map.items()}
    htype_map: ClassVar[Dict[int, str]] = {
        1: "ETHERNET",
        2: "EXPERIMENTAL",
        3: "AMATEUR",
        4: "PROTEON",
        5: "CHAOS",
        6: "IEEE",
        7: "ARCNET",
        8: "HYPERCHANNEL",
        9: "LANSTAR",
    }

    inverse_htype_map: ClassVar[Dict[str, int]] = {v: k for k, v in htype_map.items()}

    @property
    def asbytes(self):
        str2bin = lambda s: bytes([int(i, 16) for i in s.split(":")])
        packet_head = [
            self.inverse_op_map[self.op.upper()],
            self.inverse_htype_map[self.htype.upper()],
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            int(self.ciaddr),
            int(self.yiaddr),
            int(self.siaddr),
            int(self.giaddr),
            str2bin(self.chaddr).ljust(16, b"\x00"),
            self.sname.ljust(64, b"\x00"),
            self.file.ljust(128, b"\x00"),
        ]
        encoded_packet = struct.pack(self.packet_fmt, *packet_head)
        encoded_packet += self.magic_cookie
        for option in self.options:
            encoded_packet += option.asbytes
        if encoded_packet[-1] != 255:
            encoded_packet += b"\xff"
        return encoded_packet

    @property
    def msg_type(self) -> Optional[str]:
        if msg_type_option := self.options.by_code(53):
            return list(msg_type_option.value.values())[0]
        else:
            return None

    @classmethod
    def from_bytes(cls, packet: bytes):
        """
        Given a DHCP packet in bytes / wire format return a DHCPPacket object.
        """
        if packet[cls.cookie_offset_start : cls.cookie_offset_end] != cls.magic_cookie:
            raise MalformedPacketError("Magic cookie missing")
        try:
            decoded_packet = [
                field.rstrip(b"\x00") if isinstance(field, bytes) else field
                for field in struct.unpack(
                    cls.packet_fmt, packet[: cls.cookie_offset_start]
                )
            ]
        except:
            raise MalformedPacketError("Unable to parse DHCP packet")

        options_list = options.OptionList()
        read_pos = cls.cookie_offset_end
        code = 0
        while read_pos < len(packet) and code != 255:
            code = packet[read_pos]
            if code in [0, 255]:
                data_read_size = 1
            else:
                length = packet[read_pos + 1]
                data_read_size = 1 + 1 + length

            option_bytes = packet[read_pos : read_pos + data_read_size]
            options_object = OPTIONS_INTERFACE.bytes_to_object(option_bytes)
            options_list.append(options_object)
            read_pos += data_read_size

        decoded_packet.append(options_list)
        # Decode the op code
        decoded_packet[0] = cls.op_map[decoded_packet[0]]
        # Decode hardware type
        decoded_packet[1] = cls.htype_map[decoded_packet[1]]
        # Convert the ciaddr, yiaddr, siaddr, and giaddr into python IP objects
        decoded_packet[7:11] = [
            ipaddress.IPv4Address(field) for field in decoded_packet[7:11]
        ]
        # Convert MAC addr into bin string
        decoded_packet[11] = decoded_packet[11].ljust(6, b"\x00")
        bin2str = lambda b: ":".join([f"{i:02X}" for i in b])
        decoded_packet[11] = bin2str(decoded_packet[11])
        return cls(*decoded_packet)

    def format_options(self, opt_str, line_divider, line_len):
        """
        Given a string with all the options in a packet this will format
        the string into an ASCII table format.
        """
        line_pos = 0
        output = ""
        new_line = "|\n" + line_divider + "|"
        skip_next_space = False  # Need this for alignment
        last_char = ""
        for char in opt_str:
            if char == " " and skip_next_space:
                skip_next_space = False
                continue
            char = " " if last_char == "|" and char == "|" else char
            output += char
            line_pos = (line_pos + 1) % line_len
            if line_pos == 0:
                output += new_line
                skip_next_space = True
            last_char = output[-1]
        return output

    def view_packet(self):
        """
        A fun way of visualising the DHCP packet in ASCII table format.
        """
        bytes_per_line = 4
        byte_len = 15
        spacing = lambda num_bytes: (num_bytes * byte_len) + num_bytes - 1
        column = (
            lambda str_to_space, num_bytes: f"{str_to_space[:spacing(num_bytes)].center(spacing(num_bytes))}|"
        )
        line = "+" + ("-" * (byte_len * bytes_per_line + bytes_per_line))[:-1] + "+\n"
        base_packet = (
            "0                   1                   2                   3    \n"
            "0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1  \n"
            "+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n"
            "|"
            + column(f"{self.op} (1)", 1)
            + column(f"{self.htype} (1)", 1)
            + column(f"len {self.hlen} (1)", 1)
            + column(f"{self.hops} hops (1)", 1)
            + "\n"
            "+---------------+---------------+---------------+---------------+\n"
            "|" + column(f"xid=0x{self.xid:08X} (4)", 4) + "\n"
            "+-------------------------------+-------------------------------+\n"
            "|"
            + f"{self.secs} secs (2)".center(spacing(2))
            + "|"
            + f"{'BROADCAST' if self.flags else 'UNICAST'} (2)".center(spacing(2))
            + "|\n"
            "+-------------------------------+-------------------------------+\n"
            "|" + column(f"client addr: {self.ciaddr!s} (4)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|" + column(f"your addr: {self.yiaddr!s} (4)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|" + column(f"next server: {self.siaddr!s} (4)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|" + column(f"relay: {self.giaddr!s} (4)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|                                                               |\n"
            "|" + column(f"client mac: {self.chaddr}  (16)", 4) + "\n"
            "|                                                               |\n"
            "|                                                               |\n"
            "+---------------------------------------------------------------+\n"
            "|                                                               |\n"
            "|" + column(f"server name: {self.sname}   (64)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|                                                               |\n"
            "|" + column(f"boot file: {self.file} (128)", 4) + "\n"
            "+---------------------------------------------------------------+\n"
            "|"
            + column(
                f"magic cookie: {hex(int.from_bytes(self.magic_cookie, 'big'))}",
                len(self.magic_cookie),
            )
            + "\n"
            "+---------------------------------------------------------------+\n"
        )

        base_packet += "|"
        opt_str = ""
        for opt in self.options:
            opt_str += column(f"code={opt.code} (1)", 1)
            if opt.code not in [0, 255]:
                opt_str += column(f"len={opt.length} (1)", 1)
                if opt.code == 53:
                    # Shortening DHCP msg type for display -- special case
                    opt_str += column(
                        f"{opt.value[opt.key]} ({opt.length})", opt.length
                    )
                else:
                    opt_str += column(
                        f"{opt.key} {opt.value[opt.key]} ({opt.length})", opt.length
                    )

        base_packet += self.format_options(opt_str, line, spacing(bytes_per_line))

        base_packet += "\n" + line[: len(base_packet.split("\n")[-1])]
        base_packet = base_packet[:-1] + "+"
        return base_packet

    @classmethod
    def Discover(
        cls,
        mac_addr: str,
        seconds: int = 0,
        tx_id: Optional[int] = None,
        use_broadcast: bool = True,
        relay: Optional[str] = None,
        option_list: Optional[options.OptionList] = None,
    ):
        """
        Convenient constructor for a DHCP discover packet.
        """
        if not utils.is_mac_addr(mac_addr):
            raise DHCPValueError(
                "MAC address must consist of 6 octets delimited by ':'"
            )
        option_list = option_list if option_list else options.OptionList()
        option_list.insert(0, options.options.short_value_to_object(53, "DHCPDISCOVER"))
        relay_ip = ipaddress.IPv4Address(relay or 0)
        return cls(
            "BOOTREQUEST",
            cls.htype_map[1],  # 10 mb ethernet
            6,  # 6 byte hardware addr
            0,  # clients should set this to 0
            tx_id or random.getrandbits(32),
            seconds,
            0b1000_0000_0000_0000 if use_broadcast else 0,
            ipaddress.IPv4Address(0),  # Must be 0
            ipaddress.IPv4Address(0),
            ipaddress.IPv4Address(0),
            relay_ip,
            mac_addr,
            b"",
            b"",
            option_list,
        )

    @classmethod
    def Offer(
        cls,
        mac_addr: str,
        seconds: int,
        tx_id: int,
        yiaddr: Union[int, str],
        use_broadcast: bool = True,
        relay: Optional[str] = None,
        sname: bytes = b"",
        fname: bytes = b"",
        option_list: Optional[options.OptionList] = None,
    ):
        """
        Convenient constructor for a DHCP offer packet.
        """
        if len(mac_addr.split(":")) != 6 or len(mac_addr) != 17:
            raise DHCPValueError(
                "MAC address must consist of 6 octets delimited by ':'"
            )
        option_list = option_list if option_list else options.OptionList()
        option_list.insert(0, options.options.short_value_to_object(53, "DHCPOFFER"))
        relay_ip = ipaddress.IPv4Address(relay or 0)
        return cls(
            "BOOTREPLY",
            cls.htype_map[1],  # 10 mb ethernet
            6,  # 6 byte hardware addr
            0,  # clients should set this to 0
            tx_id,
            seconds,
            0b1000_0000_0000_0000 if use_broadcast else 0,
            ipaddress.IPv4Address(0),
            # yiaddr - "your address", address being proposed by server
            ipaddress.IPv4Address(yiaddr),
            ipaddress.IPv4Address(0),
            relay_ip,
            mac_addr,
            sname,
            fname,
            option_list,
        )

    @classmethod
    def Request(
        cls,
        mac_addr: str,
        seconds: int,
        tx_id: int,
        use_broadcast: bool = True,
        relay: Optional[str] = None,
        sname: bytes = b"",
        fname: bytes = b"",
        client_ip=ipaddress.IPv4Address(0),
        option_list: Optional[options.OptionList] = None,
    ):
        """
        Convenient constructor for a DHCP request packet.
        """
        if len(mac_addr.split(":")) != 6 or len(mac_addr) != 17:
            raise DHCPValueError(
                "MAC address must consist of 6 octets delimited by ':'"
            )
        option_list = option_list if option_list else options.OptionList()
        option_list.insert(0, options.options.short_value_to_object(53, "DHCPREQUEST"))
        relay_ip = ipaddress.IPv4Address(relay or 0)
        return cls(
            "BOOTREQUEST",
            cls.htype_map[1],  # 10 mb ethernet
            6,  # 6 byte hardware addr
            0,  # clients should set this to 0
            tx_id,
            seconds,
            0b1000_0000_0000_0000 if use_broadcast else 0,
            client_ip,
            ipaddress.IPv4Address(0),
            ipaddress.IPv4Address(0),
            relay_ip,
            mac_addr,
            sname,
            fname,
            option_list,
        )

    @classmethod
    def Ack(
        cls,
        mac_addr: str,
        seconds: int,
        tx_id: int,
        yiaddr: Union[int, str],
        use_broadcast: bool = True,
        relay: Optional[str] = None,
        sname: bytes = b"",
        fname: bytes = b"",
        option_list: Optional[options.OptionList] = None,
    ):
        """
        Convenient constructor for a DHCP ack packet.
        """
        # Can be refactored to just use the Request constructor if it turns out that Ack has no special needs.
        if len(mac_addr.split(":")) != 6 or len(mac_addr) != 17:
            raise DHCPValueError(
                "MAC address must consist of 6 octets delimited by ':'"
            )
        option_list = option_list if option_list else options.OptionList()
        option_list.insert(0, options.options.short_value_to_object(53, "DHCPACK"))
        relay_ip = ipaddress.IPv4Address(relay or 0)
        return cls(
            "BOOTREPLY",
            cls.htype_map[1],  # 10 mb ethernet
            6,  # 6 byte hardware addr
            0,  # clients should set this to 0
            tx_id,
            seconds,
            0b1000_0000_0000_0000 if use_broadcast else 0,
            ipaddress.IPv4Address(0),
            # yiaddr - "your address", address being proposed by server
            ipaddress.IPv4Address(yiaddr),
            ipaddress.IPv4Address(0),
            relay_ip,
            mac_addr,
            sname,
            fname,
            option_list,
        )
