class DHCPException(Exception):
    """
    Base exception for our DHCP functions
    """

class MalformedPacketError(DHCPException):
    """
    The DHCP packet has some sort of issue
    """


class DHCPValueError(DHCPException):
    """
    Something wrong with the DHCP semantics
    """


class DHCPClientError(DHCPException):
    """
    Something went wrong in the DHCP client
    """
