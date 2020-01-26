import random
import string
import datetime
import socket
import unicodedata
from typing import Dict
import importlib.resources
from . import runtime_assets


VALID_HEX = list(set(string.hexdigits.upper()))


def cur_datetime(us_precision: bool = False) -> str:
    fmt = "%Y-%m-%dT%H:%M:%S" + (".%f" if us_precision else "") + "Z"
    return datetime.datetime.now(datetime.timezone.utc).strftime(fmt)


def cur_timestamp() -> int:
    return int(datetime.datetime.utcnow().timestamp() * 10 ** 9)


def visual_length(text: str) -> int:
    """
    Given a string it returns the visual length of the string as opposed to the
    len function which returns the number of printable characters.
    """
    # See https://www.unicode.org/reports/tr11/ for how this dict in constructed
    visual_len = {
        "F": 1,
        "H": 1,
        "Na": 1,
        "N": 1,
        "W": 2,
        "A": 2,
    }
    return sum([visual_len[unicodedata.east_asian_width(char)] for char in text]) + 1


def random_mac(num_bytes: int = 6, delimiter: str = ":") -> str:
    """
    Generates an 6 byte long MAC address.

    >>> random_mac()
    'CC:AC:3C:85:A4:EF'
    """
    return delimiter.join(
        ["".join(random.choices(VALID_HEX, k=2)) for i in range(num_bytes)]
    )


def is_mac_addr(mac_addr: str) -> bool:
    """
    Returns True if the string is a valid MAC address.

    Accepts ":" or "-" as valid MAC address delimiters.
    """
    mac_addr = mac_addr.upper()
    delimiter = ":" if ":" in mac_addr else "-"
    if len(mac_addr.split(delimiter)) != 6 or len(mac_addr) != 17:
        return False
    if any([b not in VALID_HEX for b in "".join(mac_addr.split(delimiter))]):
        return False
    return True


mac_vendor_map: Dict[str, str] = {
    line.split("\t\t")[0].split(" ")[0]: line.split("\t\t")[1]
    for line in [
        line.strip()
        for line in importlib.resources.read_text(runtime_assets, "oui.txt").split("\n")
        if "(base 16)" in line
    ]
}


def mac2vendor(mac_addr: str) -> str:
    if is_mac_addr(mac_addr):
        return mac_vendor_map.get(
            mac_addr.replace(":", "").replace("-", "")[:6].upper(),
            "Unknown Manufacturer",
        )
    else:
        raise ValueError(f"{mac_addr} is not a valid MAC address")


def get_ip_by_iface(iface: str) -> str:
    rand_port = 61224
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, 25, iface.encode())
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.connect(("255.255.255.255", rand_port))
    return s.getsockname()[0]


def get_ip_by_server(server: str) -> str:
    rand_port = 61222
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((server, rand_port))
    return s.getsockname()[0]
