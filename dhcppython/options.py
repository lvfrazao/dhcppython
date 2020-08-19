"""
Provides set of classes for decoding and encoding DHCP options.

A high level API is provided by the `options` object and the Option class:

1. Create an options object from bytes by calling the `bytes_to_object` method
e.g., 

```
>>> options.bytes_to_object(b'\x3d\x07\x01\x8c\x45\x00\x1d\x48\x16')
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00\x1dH\x16')
```

2. Get a human readable dict of an options object value

```
 >>> ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00\x1dH\x16').value
{'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}}
>>> options.bytes_to_object(b'\x3d\x07\x01\x8c\x45\x00\x1d\x48\x16').value
{'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}}
```

3. Create an options object from its human readable dict of its value:

```
>>> options.value_to_object({'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}})
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00\x1dH\x16')
```

4. Convert a human readable dict of an option value to the bytes representation

```
>>> options.value_to_bytes(({'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}}))
b'=\x07\x01\x8cE\x00\x1dH\x16'
>>> [int(i) for i in options.value_to_bytes(({'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}}))]
[61, 7, 1, 140, 69, 0, 29, 72, 22]
```

5. Get the bytes representation of an option given its Option object

```
>>> ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00\x1dH\x16').asbytes
b'=\x07\x01\x8cE\x00\x1dH\x16'
```

6. Create an options object from its code and "short value"

```
>>> options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'})
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00\x1dH\x16')
```
"""
from __future__ import annotations
import csv
from abc import ABC, abstractmethod
import collections.abc
from typing import Dict, Union, List, Tuple, Optional, TypedDict
import ipaddress
import struct
import json
import importlib.resources
from .exceptions import DHCPValueError
from . import runtime_assets

OPTIONS: Dict[int, Dict[str, Union[str, int]]] = {
    int(line[0]): {
        "name": line[1],
        "len": int(line[2]) if line[2].isdigit() else line[2],
        "description": line[3],
        "rfc": line[4].split("RFC")[-1][:-1],
    }
    for line in csv.reader(importlib.resources.open_text(runtime_assets, "options.csv"))
    if line[0].isdigit()
}


class CodeDataMapping(TypedDict):
    obj: Option
    index: int


class OptionList(collections.abc.MutableSequence):
    def __init__(self, options_array: Optional[List[Option]] = None):
        self.data: List[Option] = list(options_array) if options_array else []
        self.code_to_data: Dict[int, CodeDataMapping] = {
            opt.code: {"obj": opt, "index": i} for i, opt in enumerate(self.data)
        }

    def __repr__(self):
        return f"OptionList({self.data})"

    def by_code(self, code: int) -> Optional[Option]:
        return self.code_to_data.get(code, {}).get("obj")

    def append(self, item: Option):
        if item.code not in self.code_to_data:
            self.data.append(item)
            self.code_to_data[item.code] = {"obj": item, "index": len(self.data) - 1}
        else:
            self.data[self.code_to_data[item.code]["index"]] = item
            self.code_to_data[item.code]["obj"] = item

    def insert(self, index: int, obj: Option):
        if obj.code in self.code_to_data:
            # delete previous object and insert this one at the specified pos
            del self[self.code_to_data[obj.code]["index"]]

        self.data.insert(index, obj)

        # Re-index entire list...
        for opt in self.code_to_data.values():
            if opt["index"] >= index:
                opt["index"] += 1

        self.code_to_data[obj.code] = {
            "obj": obj,
            "index": index,
        }

    def __len__(self):
        return len(self.data)

    def __getitem__(self, key: int) -> Option:
        return self.data[key]

    def __setitem__(self, key: int, value: Option):
        # Remove entry of option in current index
        for opt in self.code_to_data.values():
            if opt["index"] == key:
                del self.code_to_data[opt["obj"].code]
                break
        # update self.data list with object
        self.data[key] = value
        # reindex the object that is in the list
        self.code_to_data[value.code] = {
            "obj": value,
            "index": key,
        }
        for index, opt in enumerate(self.data):
            if opt.code == value.code and index != key:
                del self[index]
                if index < key:
                    self.code_to_data[value.code] = {
                        "obj": value,
                        "index": key,
                    }
                    break

    def __delitem__(self, key: int):
        code = self.data[key].code
        # problematic cause it reindexes the whole list
        for opt in self.code_to_data.values():
            if opt["index"] > key:
                opt["index"] -= 1
        del self.code_to_data[code]
        del self.data[key]

    def __contains__(self, other):
        if hasattr(other, "asbytes"):
            return other in self.data
        return other in self.code_to_data

    def __eq__(self, other):
        for self_item, other_item in zip(self, other):
            if not (self_item == other_item):
                return False
        return True

    def as_dict(self):
        opt_dict = {}
        for opt in self.data:
            opt_dict.update(opt.value)
        return opt_dict

    @property
    def json(self):
        return json.dumps(self.as_dict(), indent=4)


class OptionDirectory(object):
    def __init__(self):
        self.directory = {}
        self.key_code_map = {}
        temp = dict(globals())
        for obj in temp:
            try:
                cls = globals()[obj]
                code = cls.__dict__["code"]
                key = cls.__dict__["key"]
            except:
                pass
            else:
                self.directory[code] = cls
                self.key_code_map[key] = code

    def value_to_code(self, value: dict) -> int:
        code = self.key_code_map.get(list(value)[0])
        return code

    def code_to_class(self, code: int) -> Option:
        return self.directory.get(code, UnknownOption)

    def value_to_bytes(self, value: dict):
        code = self.value_to_code(value)
        return self.code_to_class(code).from_value(value).asbytes

    def value_to_object(self, value: dict):
        code = self.value_to_code(value)
        return self.code_to_class(code).from_value(value)

    def short_value_to_object(
        self, code: int, short_value: Union[str, int, bool, dict, List[int], List[str]]
    ):
        cls = self.code_to_class(code)
        return cls.from_value({cls.key: short_value})

    def bytes_to_object(self, data: bytes):
        if data[0] in [0, 255]:
            code, length, data = (data[0], 0, b"")
        else:
            code, length, data = struct.unpack(f">BB{len(data) - 2}s", data)
        return self.code_to_class(code)(code, length, data)


class Option(ABC):
    # __slots__ = ("code", "key", "length", "data", "_value", "name", "description") # Probably dont need this right now
    code: int = -1
    key = ""

    def __init__(self, code: int, length: int, data: bytes) -> None:
        global OPTIONS
        # Option code, single byte, values from 0 to 255 are valid
        if code != self.code:
            raise DHCPValueError(f"Option code does not match {code} != {self.code}")
        self.length = (
            length  # Option size (# of bytes), options 0 and 255 are fixed size (0)
        )
        self.data = data  # Option data in bytes
        self._value: Optional[dict] = None
        self.name = OPTIONS.get(self.code, {}).get("name", "Unknown")
        self.description = OPTIONS.get(self.code, {}).get("description", "Unknown")

    def __repr__(self):
        return f"{self.__class__.__name__}(code={self.code}, length={self.length}, data={self.data})"

    def __eq__(self, other):
        return self.asbytes == other.asbytes

    @property
    @abstractmethod
    def value(self):
        """
        DHCP option data in Python dict containing human readable keys and
        values
        """

    @classmethod
    @abstractmethod
    def from_value(cls, value):
        """
        Construct the option class given a dict of option kvps
        """

    @property
    def asbytes(self) -> bytes:
        """
        Wireformat for option including code and length
        """
        return struct.pack(">BB", self.code, self.length) + self.data

    def data2IParray(self) -> List[str]:
        """
        It is common to see lists of IP addrs as option values. This returns a
        list of IPs from the options data.
        """
        num_addrs = len(self.data) // 4
        return [
            str(ipaddress.IPv4Address(ip))
            for ip in struct.unpack(">" + "L" * num_addrs, self.data)
        ]

    def data2string(self) -> str:
        """
        Converts a data field to a string.
        """
        return struct.unpack(f">{len(self.data)}s", self.data)[0].decode().strip()

    def data2bool(self) -> bool:
        """
        Converts data to bool value.
        """
        return struct.unpack(">?", self.data)[0]

    def data2bin(self) -> str:
        """
        Converts data to a string representation of the binary data
        """
        return " ".join([f"0x{d:02X}" for d in self.data])

    def data2IPpairs(self) -> List[Tuple[str, str]]:
        """
        Converts data to tuples of IP pairs.
        """
        num_pairs = len(self.data) // 8
        pairs: List[Tuple[str, str]] = []
        for i in range(num_pairs):
            ip1, ip2 = [
                str(ipaddress.IPv4Address(ip))
                for ip in struct.unpack(">LL", self.data[i * 8 : (i + 1) * 8])
            ]
            pairs.append((ip1, ip2))
        return pairs

    def data2uint8(self) -> int:
        """
        Converts data to unsigned 8 bit integer.
        """
        return struct.unpack(">B", self.data)[0]

    def data2uint16(self) -> int:
        """
        Converts data to unsigned 16 bit integer.
        """
        return struct.unpack(">H", self.data)[0]

    def data2uint32(self) -> int:
        """
        Converts data to unsigned 32 bit integer.
        """
        return struct.unpack(">L", self.data)[0]

    def data2int32(self) -> int:
        """
        Converts data to signed 32 bit integer.
        """
        return struct.unpack(">l", self.data)[0]

    def data2uint8array(self) -> List[int]:
        """
        Converts data to list of unsigned 8 bit integers.
        """
        return list(struct.unpack(">" + "B" * len(self.data), self.data))

    def data2uint16array(self) -> List[int]:
        """
        Converts data to list of unsigned 16 bit integers.
        """
        return list(struct.unpack(">" + "H" * (len(self.data) // 2), self.data))

    @staticmethod
    def IParray2data(value: List[str]) -> bytes:
        """
        Converts list of IP addresses to bytes
        """
        return b"".join([ipaddress.IPv4Address(ip).packed for ip in value])

    @staticmethod
    def int32array2data(value: List[int]) -> bytes:
        """
        Converts list of int32s to bytes
        """
        return struct.pack(">" + "l" * len(value), *value)

    @staticmethod
    def uint8array2data(value: List[int]) -> bytes:
        """
        Converts list of uint8s to bytes
        """
        return struct.pack(">" + "B" * len(value), *value)

    @staticmethod
    def uint16array2data(value: List[int]) -> bytes:
        """
        Converts list of uint16s to bytes
        """
        return struct.pack(">" + "H" * len(value), *value)

    @staticmethod
    def uint32array2data(value: List[int]) -> bytes:
        """
        Converts list of uint32s to bytes
        """
        return struct.pack(">" + "L" * len(value), *value)

    @staticmethod
    def bool2data(value: bool) -> bytes:
        """
        Converts bool to bytes
        """
        return struct.pack(">?", value)

    @staticmethod
    def bin2data(value: str) -> bytes:
        """
        Converts string representing binary data to bytes
        """
        return struct.pack(
            ">" + "B" * len(value.split()), *[int(val[2:], 16) for val in value.split()]
        )


class BinOption(Option):
    """
    Generic implementation of binary option
    """

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {self.key: self.data2bin()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        is_unknown_option = True if cls.code == -1 else False
        if is_unknown_option:
            code = int(list(value)[0].split("_")[1])
            key = list(value)[0]
        else:
            code = cls.code
            key = cls.key
        data = cls.bin2data(value[key])
        return cls(code, len(data), data)


class BoolOption(Option):
    """
    Generic implementation of boolean option
    """

    @property
    def value(self) -> Dict[str, bool]:
        if self._value is None:
            self._value = {self.key: self.data2bool()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, bool]):
        data = cls.bool2data(value[cls.key])
        return cls(cls.code, len(data), data)


class StrOption(Option):
    """
    Generic implementation of string option
    """

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {self.key: self.data2string()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        data = value[cls.key].encode()
        return cls(cls.code, len(data), data)


class IPOption(Option):
    """
    Generic implementation of an IP option
    """

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {self.key: self.data2IParray()[0]}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        data = cls.IParray2data([value[cls.key]])
        return cls(cls.code, len(data), data)


class IPArrayOption(Option):
    """
    Generic implementation of an IP array
    """

    @property
    def value(self) -> Dict[str, List[str]]:
        if self._value is None:
            self._value = {self.key: self.data2IParray()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, List[str]]):
        data = cls.IParray2data(value[cls.key])
        return cls(cls.code, len(data), data)


class uint8Option(Option):
    """
    Generic implementation of an uint8 option
    """

    @property
    def value(self) -> Dict[str, int]:
        if self._value is None:
            self._value = {self.key: self.data2uint8()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, int]):
        data = cls.uint8array2data([value[cls.key]])
        return cls(cls.code, len(data), data)


class uint16Option(Option):
    """
    Generic implementation of an uint16 option
    """

    @property
    def value(self) -> Dict[str, int]:
        if self._value is None:
            self._value = {self.key: self.data2uint16()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, int]):
        data = cls.uint16array2data([value[cls.key]])
        return cls(cls.code, len(data), data)


class uint32Option(Option):
    """
    Generic implementation of an uint32 option
    """

    @property
    def value(self) -> Dict[str, int]:
        if self._value is None:
            self._value = {self.key: self.data2uint32()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, int]):
        data = cls.uint32array2data([value[cls.key]])
        return cls(cls.code, len(data), data)


class uint8ArrayOption(Option):
    """
    Generic implementation of an uint8 array option
    """

    @property
    def value(self) -> Dict[str, List[int]]:
        if self._value is None:
            self._value = {self.key: self.data2uint8array()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, List[int]]):
        data = cls.uint8array2data(value[cls.key])
        return cls(cls.code, len(data), data)


class uint16ArrayOption(Option):
    """
    Generic implementation of an uint16 array option
    """

    @property
    def value(self) -> Dict[str, List[int]]:
        if self._value is None:
            self._value = {self.key: self.data2uint16array()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, List[int]]):
        data = cls.uint16array2data(value[cls.key])
        return cls(cls.code, len(data), data)


class int32Option(Option):
    """
    Generic implementation of an int32 option
    """

    @property
    def value(self) -> Dict[str, int]:
        if self._value is None:
            self._value = {self.key: self.data2int32()}
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, int]):
        data = cls.int32array2data([value[cls.key]])
        return cls(cls.code, len(data), data)


class Pad(Option):
    """
    Option 0
    
    The pad option can be used to cause subsequent fields to align on word
    boundaries.
    """

    code = 0
    key = "pad_option"

    @property
    def value(self) -> Dict[str, str]:
        return {self.key: ""}

    @classmethod
    def from_value(cls, value: dict):
        return cls(0, 0, b"")

    @property
    def asbytes(self) -> bytes:
        return b"\x00"


class End(Option):
    """
    Option 255

    End
    """

    code = 255
    key = "end_option"

    @property
    def value(self) -> Dict[str, str]:
        return {self.key: ""}

    @classmethod
    def from_value(cls, value: dict):
        return cls(255, 0, b"")

    @property
    def asbytes(self):
        return b"\xff"


class SubnetMask(IPOption):
    """
    Option 1
    Subnet Mask
    If both the subnet mask and the router option are specified in a DHCP
    reply, the subnet mask option MUST be first.

    e.g., 255.255.255.0

    Option value defined as {"subnet_mask": '255.255.255.0'}
    """

    code = 1
    key = "subnet_mask"


class TimeOffset(int32Option):
    """
    Option 2
    Time Offset
    Specifies the offset of the client's subnet in seconds from Coordinated
    Universal Time (UTC).

    e.g., 3600 seconds (+1 hours)
    Option value defined as {"time_offset_s": 3600, "time_offset_h": 1]}
    """

    code = 2
    key = "time_offset_s"


class Router(IPArrayOption):
    """
    Option 3
    Specifies a list of IP addresses for routers on the client's subnet.
    Routers SHOULD be listed in order of preference.

    Minimum length for the router option is 4 octets, and the length MUST
    always be a multiple of 4.

    e.g., 192.168.0.1
    Option value defined as {"routers": ['1.1.1.1', '2.2.2.2']}
    """

    code = 3
    key = "routers"


class TimeServer(IPArrayOption):
    """
    Option 4
    Specifies a list of RFC 868 [6] time servers available to the client.
    Servers SHOULD be listed in order of preference.

    The minimum length for
    this option is 4 octets, and the length MUST always be a multiple of
    4.

    Option value defined as {"time_servers": ['1.1.1.1', ...]}
    """

    code = 4
    key = "time_servers"


class NameServer(IPArrayOption):
    """
    Option 5

    Specifies a list of IEN 116 name servers available to the client.

    Listed in order, multiple of 4

    Option value defined as {"name_servers": ['1.1.1.1', ...]}
    """

    code = 5
    key = "name_servers"


class DNSServer(IPArrayOption):
    """
    Option 6

    Specifies a list of Domain Name System (STD 13, RFC 1035) name servers
    available.

    Listed in order, multiple of 4

    Option value defined as {"dns_servers": ['1.1.1.1', ...]}
    """

    code = 6
    key = "dns_servers"


class LogServer(IPArrayOption):
    """
    Option 7
    
    Specifies a list of MIT-LCS UDP log servers available to the client.

    Listed in order, multiple of 4

    Option value defined as {"log_servers": ['1.1.1.1', ...]}
    """

    code = 7
    key = "log_servers"


class CookieServer(IPArrayOption):
    """
    Option 8

    Specifies a list of RFC 865 [9] cookie servers available to the client.

    Listed in order, multiple of 4
    Option value defined as {"cookie_servers": ['1.1.1.1', ...]}
    """

    code = 8
    key = "cookie_servers"


class LPRServer(IPArrayOption):
    """
    Option 9

    Specifies a list of RFC 1179 [10] line printer servers available to the client.

    Listed in order, multiple of 4
    Option value defined as {"lpr_servers": ['1.1.1.1', ...]}
    """

    code = 9
    key = "lpr_servers"


class ImpressServer(IPArrayOption):
    """
    Option 10

    Specifies a list of Imagen Impress servers available to the client.

    Listed in order, multiple of 4
    Option value defined as {"impress_servers": ['1.1.1.1', ...]}
    """

    code = 10
    key = "impress_servers"


class ResourceLocationServer(IPArrayOption):
    """
    Option 11

    Specifies a list of RFC 887 [11] Resource Location servers available to the client.

    Listed in order, multiple of 4
    Option value defined as {"resource_location_servers": ['1.1.1.1', ...]}
    """

    code = 11
    key = "resource_location_servers"


class Hostname(StrOption):
    """
    Option 12

    Specifies the name of the client.  The name may or may not be qualified
    with the local domain name (see section 3.17 for the preferred way to
    retrieve the domain name).  See RFC 1035 for character set restrictions.
    
    Min len 1
    Option value defined as {"hostname": "laptop01"}
    """

    code = 12
    key = "hostname"


class BootfileSize(uint16Option):
    """
    Option 13

    Specifies the length in 512-octet blocks of the default boot image for
    the client.

    Len 2
    Option value defined as {"bootfile_size": 256}
    """

    code = 13
    key = "bootfile_size"


class MeritDumpFile(StrOption):
    """
    Option 14

    Specifies the path-name of a file to which the client's core image
    should be dumped in the event the client crashes.
    
    Min len 1
    Option value defined as {"merit_dump_file": "something"}
    """

    code = 14
    key = "merit_dump_file"


class DomainName(StrOption):
    """
    Option 15

    Specifies the domain name that client should use when resolving
    hostnames via the Domain Name System.

    Min len 1
    Option value defined as {"domain_name": "google.com"}
    """

    code = 15
    key = "domain_name"


class SwapServer(IPOption):
    """
    Option 16

    Sspecifies the IP address of the client's swap server.
    
    Len 4
    Option value defined as {"swap_server": "1.1.1.1"}
    """

    code = 16
    key = "swap_server"


class RootPath(StrOption):
    """
    Option 17

    Specifies the path-name that contains the client's root disk.

    Min len 1
    Option value defined as {"root_path": "something"}
    """

    code = 17
    key = "root_path"


class ExtensionPath(StrOption):
    """
    Option 18

    String to specify a file, retrievable via TFTP, which contains
    information which can be interpreted in the same way as the 64-octet
    vendor-extension field within the BOOTP response.

    Option value defined as {"extensions_path": "something"}
    """

    code = 18
    key = "extensions_path"


class IPForwarding(BoolOption):
    """
    Option 19

    Specifies whether the client should configure its IP layer for packet
    forwarding.

    Option value defined as {"ip_forwarding": True}
    """

    code = 19
    key = "ip_forwarding"


class NonLocalSourceRouting(BoolOption):
    """
    Option 20

    Specifies whether the client should configure its IP layer to allow
    forwarding of datagrams with non-local source routes.
    
    Option value defined as {"non_local_source_routing": True}
    """

    code = 20
    key = "non_local_source_routing"


class PolicyFilter(Option):
    """
    Option 21

    Specifies policy filters for non-local source routing. The filters
    consist of a list of IP addresses and masks which specify
    destination/mask pairs with which to filter incoming source routes.
    
    Option value defined as:
    {
        "policy_filters": [{"address": "1.1.1.1", "mask": "255.255.255.0"}, ...]
    }
    """

    code = 21
    key = "policy_filters"

    @property
    def value(self) -> Dict[str, List[Dict[str, str]]]:
        if self._value is None:
            self._value = {
                self.key: [
                    {"address": pair[0], "mask": pair[1]}
                    for pair in self.data2IPpairs()
                ]
            }
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, List[Dict[str, str]]]):
        ip_array: List[str] = []
        for pair in value[cls.key]:
            ip_array.extend(pair.values())
        data = cls.IParray2data(ip_array)
        return cls(cls.code, len(data), data)


class MaxDGRAMReassemblySize(uint16Option):
    """
    Option 22

    Specifies the maximum size datagram that the client should be prepared
    to reassemble.

    Option value defined as {"max_datagram_reassembly_size": 512}
    """

    code = 22
    key = "max_datagram_reassembly_size"


class IPTTL(uint8Option):
    """
    Option 23
    
    Specifies the default time-to-live that the client should use on
    outgoing datagrams.

    Object value is defined as: {"default_ip_ttl": 123}
    """

    code = 23
    key = "default_ip_ttl"


class PathMTUAgingTimeout(uint32Option):
    """
    Option 24

    Specifies the timeout (in seconds) to use when aging Path MTU values
    discovered by the mechanism defined.

    Len 4
    Object value is defined as: {"path_MTU_aging_timeout":1234}
    """

    code = 24
    key = "path_MTU_aging_timeout"


class PathMTUAgingTable(uint16ArrayOption):
    """
    Option 25

    Specifies a table of MTU sizes to use when performing Path MTU Discovery
    as defined in RFC 1191.

    Object value defined as: {"path_mtu_aging_table": [123, 234, ...]}
    """

    code = 25
    key = "path_mtu_aging_table"


class InterfaceMTU(uint16Option):
    """
    Option 26

    Specifies the MTU to use on this interface.
    Object value defined as: {"interface_mtu": 1234}
    """

    code = 26
    key = "interface_mtu"


class AllSubnetsLocal(BoolOption):
    """
    Option 27

    Specifies whether or not the client may assume that all subnets of the
    IP network to which the client is connected use the same MTU as the
    subnet of that network to which the client is directly connected.
    
    Option value defined as: {"all_subnets_local": True}
    """

    code = 27
    key = "all_subnets_local"


class BroadcastAddress(IPOption):
    """
    Option 28

    Specifies the broadcast address in use on the client's subnet.

    Objected defined as: {"broadcast_address": "1.1.1.1"}
    """

    code = 28
    key = "broadcast_address"


class PerformMaskDiscovery(BoolOption):
    """
    Option 29

    Specifies whether or not the client should perform subnet mask
    discovery using ICMP.

    Object value defined as: {"perform_mask_discovery"}
    """

    code = 29
    key = "perform_mask_discovery"


class MaskSupplier(BoolOption):
    """
    Option 30

    Specifies whether or not the client should respond to subnet mask
    requests using ICMP.

    Object defined as: {"mask_supplier": True}
    """

    code = 30
    key = "mask_supplier"


class PerformRouterDiscovery(BoolOption):
    """
    Option 31

    Specifies whether or not the client should solicit routers using the
    Router Discovery mechanism defined in RFC 1256 [13].

    Object defined as: {"perform_router_discovery": True}
    """

    code = 31
    key = "perform_router_discovery"


class RouterSolicitationAddress(IPOption):
    """
    Option 32

    Specifies the address to which the client should transmit router
    solicitation requests.

    Option value defined as: {"router_solicitation_address": "1.1.1.1"}
    """

    code = 32
    key = "router_solicitation_address"


class StaticRoute(Option):
    """
    Option 33

    Specifies a list of static routes that the client should install in its
    routing cache. If multiple routes to the same destination are specified,
    they are listed in descending order of priority.
    """

    code = 33
    key = "static_routes"

    @property
    def value(self) -> Dict[str, List[Dict[str, str]]]:
        if self._value is None:
            self._value = {
                self.key: [
                    {"destination": pair[0], "router": pair[1]}
                    for pair in self.data2IPpairs()
                ]
            }
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, List[Dict[str, str]]]):
        ip_array: List[str] = []
        for pair in value[cls.key]:
            ip_array.extend(pair.values())
        data = cls.IParray2data(ip_array)
        return cls(cls.code, len(data), data)


class TrailerEncapsulation(BoolOption):
    """
    Option 34

    Specifies whether or not the client should negotiate the use of trailers
    (RFC 893 [14]) when using the ARP protocol. 
    
    Option value defined as: {"trailer_encapsulation": True}
    """

    code = 34
    key = "trailer_encapsulation"


class ARPCacheTimeout(uint32Option):
    """
    Option 35

    Specifies the timeout in seconds for ARP cache entries.
    
    Option value defined as: {"arp_cache_timeout": 123}
    """

    code = 35
    key = "arp_cache_timeout"


class EthernetEncapsulation(BoolOption):
    """
    Option 36

    Specifies whether or not the client should use Ethernet Version 2
    (RFC 894 [15]) or IEEE 802.3 (RFC 1042 [16]) encapsulation if the
    interface is an Ethernet.

    Option value defined as: {"ethernet_encapsulation": True}
    """

    code = 36
    key = "ethernet_encapsulation"


class TCPDefaultTTL(uint8Option):
    """
    Option 37

    Specifies the default TTL that the client should use when sending TCP
    segments.

    Option value defined as: {"tcp_default_ttl": 123}
    """

    code = 37
    key = "tcp_default_ttl"


class TCPKeepaliveInterval(uint32Option):
    """
    Option 38

    Specifies the interval (in seconds) that the client TCP should wait
    before sending a keepalive message on a TCP connection.

    Option value defined as: {"tcp_keepalive_interval": 123}
    """

    code = 38
    key = "tcp_keepalive_interval"


class TCPKeepaliveGarbage(BoolOption):
    """
    Option 39

    Specifies the whether or not the client should send TCP keepalive
    messages with a octet of garbage for compatibility with older
    implementations.

    Option value defined as: {"tcp_keepalive_garbage": True}
    """

    code = 39
    key = "tcp_keepalive_garbage"


class NISDomain(StrOption):
    """
    Option 40

    Specifies the name of the client's NIS [17] domain.
    
    Option value defined as: {"network_information_service_domain": "google.com"}
    """

    code = 40
    key = "network_information_service_domain"


class NISServer(IPArrayOption):
    """
    Option 41

    Specifies a list of IP addresses indicating NIS servers available to
    the client.
    
    Option value defined as: {"network_information_servers": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 41
    key = "network_information_servers"


class NTPServers(IPArrayOption):
    """
    Option 42

    Specifies a list of IP addresses indicating NTP [18] servers available
    to the client.
    
    Option value defined as: {"ntp_servers": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 42
    key = "ntp_servers"


class VendorSpecificInformation(BinOption):
    """
    Option 43

    Super complicated, basically arbitrary data. This option can redefine
    any option other than 0 and 255.
    
    Option value defined as: {"vender_specific_information": "0x0b 0x1c ..."}
    """

    code = 43
    key = "vendor_specific_information"


class NetbiosNameServer(IPArrayOption):
    """
    Option 44

    Specifies a list of RFC 1001/1002 [19] [20] NBNS name servers listed in
    order of preference.

    Option value defined as: {"netbios_name_servers": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 44
    key = "netbios_name_servers"


class NetbiosDatagramDistributionServer(IPArrayOption):
    """
    Option 45

    Specifies a list of RFC 1001/1002 NBDD servers listed in order of
    preference.

    Option value defined as: {"netbios_datagram_distribution_server": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 45
    key = "netbios_datagram_distribution_server"


class NetbiosNodeType(Option):
    """
    Option 46

    Node type option allows NetBIOS over TCP/IP clients which are
    configurable to be configured as described in RFC 1001/1002.

    Option value defined as: {"netbios_node_type": "B-node"}
    """

    code = 46
    key = "netbios_node_type"

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {
                self.key: {0x1: "B-node", 0x2: "P-node", 0x4: "M-node", 0x8: "H-node"}[
                    int.from_bytes(self.data, "big")
                ]
            }
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        data = {
            "B-node": b"\x01",
            "P-node": b"\x02",
            "M-node": b"\x04",
            "H-node": b"\x08",
        }[value[cls.key]]
        return cls(cls.code, len(data), data)


class NetbiosScope(StrOption):
    """
    Option 47

    Specifies the NetBIOS over TCP/IP scope parameter for the client as
    specified in RFC 1001/1002.

    Option value defined as: {"netbios_scope": "something"}
    """

    code = 47
    key = "netbios_scope"


class NetbiosXWindowSystemFontServer(IPArrayOption):
    """
    Option 48

    Specifies a list of X Window System [21] Font servers available to the
    client.

    Option value defined as: {"netbios_x_window_system_font_servers": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 48
    key = "netbios_x_window_system_font_servers"


class XWindowSystemDisplayManager(IPArrayOption):
    """
    Option 49

    Specifies a list of IP addresses of systems that are running the X
    Window System Display Manager and are available to the client.
    
    Option value is defined as: {"x_window_system_display_manager": ["1.1.1.1", "2.2.2.2"]}
    """

    code = 49
    key = "x_window_system_display_manager"


class RequestedIPAddress(IPOption):
    """
    Option 50

    This option is used in a client request (DHCPDISCOVER) to allow the
    client to request that a particular IP address be assigned.
    
    Option value is defined as: {"requested_ip_address": "1.1.1.1"} 
    """

    code = 50
    key = "requested_ip_address"


class IPAddressLeaseTime(uint32Option):
    """
    Option 51

    This option is used in a client request (DHCPDISCOVER or DHCPREQUEST)
    to allow the client to request a lease time for the IP address.  In a
    server reply (DHCPOFFER), a DHCP server uses this option to specify the
    lease time it is willing to offer.
    """

    code = 51
    key = "lease_time"


class Overload(Option):
    """
    Option 52
    
    This option is used to indicate that the DHCP 'sname' or 'file' fields
    are being overloaded by using them to carry DHCP options. A DHCP server
    inserts this option if the returned parameters will exceed the usual
    space allotted for options.
    """

    code = 52
    key = "option_overload"

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {
                self.key: {
                    1: "'file' field is used to hold options",
                    2: "'sname' field is used to hold options",
                    3: "both fields are used to hold options",
                }[int.from_bytes(self.data, "big")]
            }
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        data = {
            "'file' field is used to hold options": b"\x01",
            "'sname' field is used to hold options": b"\x02",
            "both fields are used to hold options": b"\x03",
        }[value[cls.key]]
        return cls(cls.code, len(data), data)


class MessageType(Option):
    """
    Option 53

    This option is used to convey the type of the DHCP message.
    """

    code = 53
    key = "dhcp_message_type"

    @property
    def value(self) -> Dict[str, str]:
        if self._value is None:
            self._value = {
                self.key: {
                    1: "DHCPDISCOVER",
                    2: "DHCPOFFER",
                    3: "DHCPREQUEST",
                    4: "DHCPDECLINE",
                    5: "DHCPACK",
                    6: "DHCPNAK",
                    7: "DHCPRELEASE",
                    8: "DHCPINFORM",
                }[int.from_bytes(self.data, "big")]
            }
        return self._value

    @classmethod
    def from_value(cls, value: Dict[str, str]):
        data = {
            "DHCPDISCOVER": b"\x01",
            "DHCPOFFER": b"\x02",
            "DHCPREQUEST": b"\x03",
            "DHCPDECLINE": b"\x04",
            "DHCPACK": b"\x05",
            "DHCPNAK": b"\x06",
            "DHCPRELEASE": b"\x07",
            "DHCPINFORM": b"\x08",
        }[value[cls.key]]
        return cls(cls.code, len(data), data)


class ServerIdentifier(IPOption):
    """
    Option 54

    This option is used in DHCPOFFER and DHCPREQUEST messages, and may
    optionally be included in the DHCPACK and DHCPNAK messages.
    """

    code = 54
    key = "dhcp_server"


class ParameterRequestList(uint8ArrayOption):
    """
    Option 55

    This option is used by a DHCP client to request values for specified
    configuration parameters.  The list of requested parameters is
    specified as n octets, where each octet is a valid DHCP option code
    as defined in this document.
    """

    code = 55
    key = "parameter_request_list"


class Message(StrOption):
    """
    Option 56

    This option is used by a DHCP server to provide an error message to a
    DHCP client in a DHCPNAK message in the event of a failure. A client
    may use this option in a DHCPDECLINE message to indicate the why the
    client declined the offered parameters.
    """

    code = 56
    key = "message"


class MaxDHCPMessageSize(uint16Option):
    """
    Option 57

    This option specifies the maximum length DHCP message that it is
    willing to accept.
    """

    code = 57
    key = "max_dhcp_message_size"


class RenewalTime(uint32Option):
    """
    Option 58

    This option specifies the time interval from address assignment until
    the client transitions to the RENEWING state.
    """

    code = 58
    key = "renewal_time"


class RebindingTime(uint32Option):
    """
    Option 59

    This option specifies the time interval from address assignment until
    the client transitions to the REBINDING state.
    """

    code = 59
    key = "rebinding_time"


class VendorClassIdentifier(StrOption):
    """
    Option 60

    This option is used by DHCP clients to optionally identify the vendor
    type and configuration of a DHCP client.
    """

    code = 60
    key = "vendor_class_identifier"


class ClientIdentifier(Option):
    """
    Option 61

    This option is used by DHCP clients to specify their unique
    identifier.  DHCP servers use this value to index their database of
    address bindings.  This value is expected to be unique for all
    clients in an administrative domain.
    """

    code = 61
    key = "client_identifier"

    @property
    def value(self) -> Dict[str, Dict[str, str]]:
        if self._value is None:
            hwtype, hwaddr = struct.unpack(">B6s", self.data)
            self._value = {
                self.key: {
                    "hwtype": hwtype,
                    "hwaddr": ":".join([f"{b:02X}" for b in hwaddr]),
                }
            }
        return self._value

    @classmethod
    def from_value(cls, value):
        hwtype = value[cls.key]["hwtype"]
        hwaddr = value[cls.key]["hwaddr"]
        data = struct.pack(">B", hwtype) + struct.pack(
            ">" + "B" * len(hwaddr.split(":")), *[int(i, 16) for i in hwaddr.split(":")]
        )
        return cls(cls.code, len(data), data)


class NISPlusDomain(StrOption):
    """
    Option 64

    Specifies the name of the client's NIS+ [17] domain.
    """

    code = 64
    key = "nis_plus_domain"


class NISPlusServers(IPArrayOption):
    """
    Option 65

    Specifies a list of IP addresses indicating NIS+ servers available to
    the client.
    """

    code = 65
    key = "nis_plus_servers"


class TFTPServerName(StrOption):
    """
    Option 66

    This option is used to identify a TFTP server when the 'sname' field in
    the DHCP header has been used for DHCP options.
    """

    code = 66
    key = "tftp_server_name"


class BootfileName(StrOption):
    """
    Option 67

    This option is used to identify a bootfile when the 'file' field in the
    DHCP header has been used for DHCP options.
    """

    code = 67
    key = "bootfile_name"


class MobileIPHomeAgent(IPArrayOption):
    """
    Option 68

    Specifies a list of IP addresses indicating mobile IP home agents
    available to the client.
    """

    code = 68
    key = "mobile_ip_home_agent"


class SMTPServer(IPArrayOption):
    """
    Option 69

    Specifies a list of SMTP servers available to the client.
    """

    code = 69
    key = "smtp_servers"


class POP3Server(IPArrayOption):
    """
    Option 70

    Specifies a list of POP3 available to the client.
    """

    code = 70
    key = "pop3_servers"


class NNTPServer(IPArrayOption):
    """
    Option 71

    Specifies a list of NNTP available to the client.
    """

    code = 71
    key = "nntp_servers"


class WWWServer(IPArrayOption):
    """
    Option 72

    Specifies a list of WWW available to the client.
    """

    code = 72
    key = "world_wide_web_servers"


class FingerServer(IPArrayOption):
    """
    Option 73

    Specifies a list of Finger available to the client.
    """

    code = 73
    key = "finger_servers"


class IRCServer(IPArrayOption):
    """
    Option 74

    Specifies a list of IRC available to the client.
    """

    code = 74
    key = "irc_servers"


class StreetTalkServer(IPArrayOption):
    """
    Option 75

    Specifies a list of StreetTalk servers available to the client.
    """

    code = 75
    key = "streettalk_servers"


class StreetTalkDirectoryAssistanceServer(IPArrayOption):
    """
    Option 76

    Specifies a list of STDA servers available to the client.
    """

    code = 76
    key = "stda_servers"


class RelayAgentInformation(StrOption):
    """
    Option 82

    Relay Agent Information
    """

    code = 82
    key = "relay_agent_info"


class UnknownOption(BinOption):
    """
    Represents any options not defined here.
    """

    def __init__(self, code, length, data):
        self.code = code
        self.key = (
            "".join(OPTIONS.get(code, {}).get("name", "Unknown").split()) + f"_{code}"
        )
        super().__init__(code, length, data)


# this should come after the last option is defined
options = OptionDirectory()
