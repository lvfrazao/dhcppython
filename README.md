# DHCP Python

Version 0.1.1

A Python implementation of a DHCP client and the tools to manipulate DHCP packets. Includes:

1. A parser of DHCP packets, returning Python objects
2. Supports for all DHCP options in RFC 2132
3. A rudimentary DHCP client

## Installation

`pip install dhcppython`

## Requirements

* Python 3.8.0 or higher

**NOTE: This has been tested on Ubuntu 18.04 and Windows WSL. May or may not work on other platforms.**

## The Packet Parser

Two files contribute to the packet parsing: `dhcppython.packet` and `dhcppython.options`. For most operations only `dhcppython.packet` will be required.

### dhcppython.packet

The main class in `dhcppython.packet` is the `DHCPPacket`. The `DHCPPacket` class contains multiple constructors for parsing and constructing DHCP packets. 

#### Converting a packet in wireformat to a Python object

Given a DHCP packet in `bytes` format (such as what you would get from reading a DHCP packet straight from a socket) a DHCPPacket object can be instantiated by calling the `from_bytes` and supplying the bytes.

```python
>>> pkt = dhcppython.packet.DHCPPacket.from_bytes(b'\x01\x01\x06\x00\xea\xbe\xc3\x97\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8cE\x00E\x12\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x01=\x07\x01\x8cE\x00E\x12\t9\x02\x05\xdc<\x0eandroid-dhcp-9\x0c\tGalaxy-S97\n\x01\x03\x06\x0f\x1a\x1c3:;+\xff')
>>> pkt
DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=3938370455, secs=1, flags=0, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='8C:45:00:45:12:09', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x01'), ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00E\x12\t'), MaxDHCPMessageSize(code=57, length=2, data=b'\x05\xdc'), VendorClassIdentifier(code=60, length=14, data=b'android-dhcp-9'), Hostname(code=12, length=9, data=b'Galaxy-S9'), ParameterRequestList(code=55, length=10, data=b'\x01\x03\x06\x0f\x1a\x1c3:;+'), End(code=255, length=0, data=b'')]))
```

#### Converting a DHCPPacket object to wireformat

Given a DHCPPacket object you can easily output the corresponding DHCP packet in wireformat by accessing the `asbytes` attribute of the object.

```python
>>> pkt.asbytes
b'\x01\x01\x06\x00\xea\xbe\xc3\x97\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8cE\x00E\x12\t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x01=\x07\x01\x8cE\x00E\x12\t9\x02\x05\xdc<\x0eandroid-dhcp-9\x0c\tGalaxy-S97\n\x01\x03\x06\x0f\x1a\x1c3:;+\xff'
```

This bytes output is suitable for sending over a socket to a DHCP server.

#### Other Constructors of the DHCPPacket Class

* The default, low level, constructor (not recommended):

```python
>>> pkt = dhcppython.packet.DHCPPacket(op="BOOTREQUEST", htype="ETHERNET", hlen=6, hops=0, xid=123456, secs=0, flags=0, ciaddr=ipaddress.IPv4Address(0), yiaddr=ipaddress.IPv4Address(0), siaddr=ipaddress.IPv4Address(0), giaddr=ipaddress.IPv4Address(0), chaddr="DE:AD:BE:EF:C0:DE", sname=b'', file=b'', options=dhcppython.options.OptionList([dhcppython.options.options.short_value_to_object(53, "DHCPDISCOVER")]))
>>> pkt
DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=123456, secs=0, flags=0, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='DE:AD:BE:EF:C0:DE', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x01')]))
```

* Higher level constructors specific to the four main DHCP message types: DISCOVER, OFFER, REQUEST, ACK:

```python
>>> dhcppython.packet.DHCPPacket.Discover('de:ad:be:ef:c0:de')
DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=4249353806, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x01')]))
>>> dhcppython.packet.DHCPPacket.Offer('de:ad:be:ef:c0:de', seconds=0, tx_id=4249353806, yiaddr=ipaddress.IPv4Address('192.168.56.4'))
DHCPPacket(op='BOOTREPLY', htype='ETHERNET', hlen=6, hops=0, xid=4249353806, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('192.168.56.4'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x02')]))
>>> dhcppython.packet.DHCPPacket.Request('de:ad:be:ef:c0:de', seconds=0, tx_id=4249353806)
DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=4249353806, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x03')]))
>>> dhcppython.packet.DHCPPacket.Ack('de:ad:be:ef:c0:de', seconds=0, tx_id=4249353806, yiaddr=ipaddress.IPv4Address('192.168.56.4'))
DHCPPacket(op='BOOTREPLY', htype='ETHERNET', hlen=6, hops=0, xid=4249353806, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('192.168.56.4'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x05')]))
```

### dhcppython.options

This module provides classes for:

1. All DHCP options described in RFC 2132
2. An unknown option class for options not encoded
3. An abstract Option class that is easily extendable if additional options are required
4. A data structure for mananging DHCP options - the `OptionList`
5. An higher lever Option factory - the `OptionDirectory`

A high level API is provided by the `dhcppython.options.options` object and the Option class:

* Create an options object from bytes by calling the `bytes_to_object` method

```python
>>> opt = dhcppython.options.options.bytes_to_object(b"\x3d\x07\x01\x8c\x45\x00\x45\x12\x09")
>>> opt
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00E\x12\t')
```

* Get a human readable dict of an options object value

```python
>>> opt.value
{'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:45:12:09'}}
```

* Create an options object from its human readable dict of its value:

```python
>>> dhcppython.options.options.value_to_object({'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:45:12:09'}})
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00E\x12\t')
```

OR

```python
>>> dhcppython.options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': '8C:45:00:45:12:09'})
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00E\x12\t')
```

4. Convert a human readable dict of an option value to the bytes representation

```python
>>> dhcppython.options.options.value_to_bytes({'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:45:12:09'}})
b'=\x07\x01\x8cE\x00E\x12\t'
```

5. Get the bytes representation of an option given its Option object

```python
>>> opt = dhcppython.options.ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00E\x12\t')
>>> opt.asbytes
b'=\x07\x01\x8cE\x00E\x12\t'
```

The `OptionList` class provides a very convenient set of methods for managing a list of DHCP options.

* Create an `OptionList` instance from a list of `Option` objects

```python
>>> opt_list = dhcppython.options.OptionList(
...             [
...                 dhcppython.options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:23:45:67"}),
...                 dhcppython.options.options.short_value_to_object(57, 1500),
...                 dhcppython.options.options.short_value_to_object(60, "android-dhcp-9"),
...                 dhcppython.options.options.short_value_to_object(12, "Galaxy-S9"),
...                 dhcppython.options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
...             ]
...         )
>>> opt_list
OptionList([ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00#Eg'), MaxDHCPMessageSize(code=57, length=2, data=b'\x05\xdc'), VendorClassIdentifier(code=60, length=14, data=b'android-dhcp-9'), Hostname(code=12, length=9, data=b'Galaxy-S9'), ParameterRequestList(code=55, length=10, data=b'\x01\x03\x06\x0f\x1a\x1c3:;+')])
```

* Retrieve any options in the `OptionList` by its option code

```python
>>> opt_list.by_code(12)
Hostname(code=12, length=9, data=b'Galaxy-S9')
>>> opt_list.by_code(13)
>>>
```

* Append (add) any options using the `append` method

```python
>>> opt_list.append(dhcppython.options.options.short_value_to_object(53, "DHCPDISCOVER"))
>>> opt_list
OptionList([ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00#Eg'), MaxDHCPMessageSize(code=57, length=2, data=b'\x05\xdc'), VendorClassIdentifier(code=60, length=14, data=b'android-dhcp-9'), Hostname(code=12, length=9, data=b'Galaxy-S9'), ParameterRequestList(code=55, length=10, data=b'\x01\x03\x06\x0f\x1a\x1c3:;+'), MessageType(code=53, length=1, data=b'\x01')])
```

* Protects against duplicate options (duplicate overwrites in place)

```python
>>> opt_list
OptionList([ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00#Eg'), MaxDHCPMessageSize(code=57, length=2, data=b'\x13\x88'), VendorClassIdentifier(code=60, length=14, data=b'android-dhcp-9'), Hostname(code=12, length=9, data=b'Galaxy-S9'), ParameterRequestList(code=55, length=10, data=b'\x01\x03\x06\x0f\x1a\x1c3:;+'), MessageType(code=53, length=1, data=b'\x01')])
```

* Allows for iteration like a list

```python
>>> for opt in opt_list:
...     print(opt)
...
ClientIdentifier(code=61, length=7, data=b'\x01\x8cE\x00#Eg')
MaxDHCPMessageSize(code=57, length=2, data=b'\x13\x88')
VendorClassIdentifier(code=60, length=14, data=b'android-dhcp-9')
Hostname(code=12, length=9, data=b'Galaxy-S9')
ParameterRequestList(code=55, length=10, data=b'\x01\x03\x06\x0f\x1a\x1c3:;+')
MessageType(code=53, length=1, data=b'\x01')
```

## The DHCP Client

A very primitive DHCP client is included in this package in the `dhcppython.client` module. The client is able to negotiate a lease with a DHCP server and can be configured to use:

* A given interface
* Option to send broadcast packets or unicast packets to a specific server
* Set a relay in the giaddr field
* "Spoof" MAC addresses
* Specify options to send with request

The high level interface to negotiate a lease is the `get_lease` method of the `dhcppython.client.DHCPClient` object. This method goes through the DORA DHCP handshake and returns a `Lease` namedtuple which includes all the packets in the :

```python
>>> import dhcppython
>>> client = dhcppython.client.DHCPClient(interface="enp0s8")
>>> lease = client.get_lease(mac_addr="de:ad:be:ef:c0:de", broadcast=True, relay=None, server="255.255.255.255", options_list=None)
Lease succesful: 192.168.56.3 -- DE:AD:BE:EF:C0:DE -- 3 ms elapsed
>>> lease
Lease(discover=DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=2829179566, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x01')])), offer=DHCPPacket(op='BOOTREPLY', htype='ETHERNET', hlen=6, hops=0, xid=2829179566, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('192.168.56.3'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='DE:AD:BE:EF:C0:DE', sname=b'', file=b'', options=OptionList([SubnetMask(code=1, length=4, data=b'\xff\xff\xff\x00'), Router(code=3, length=4, data=b'\n\x97\x01\x01'), DNSServer(code=6, length=4, data=b'\nh\x01\x08'), Hostname(code=12, length=22, data=b'dhcp.-192-168-56-3.com'), DomainName(code=15, length=14, data=b'example.com'), IPAddressLeaseTime(code=51, length=4, data=b'\x00\x01Q\x80'), MessageType(code=53, length=1, data=b'\x02'), ServerIdentifier(code=54, length=4, data=b'\xc0\xa88\x02'), RenewalTime(code=58, length=4, data=b'\x00\x00T`'), RebindingTime(code=59, length=4, data=b'\x00\x00\xa8\xc0'), End(code=255, length=0, data=b'')])), request=DHCPPacket(op='BOOTREQUEST', htype='ETHERNET', hlen=6, hops=0, xid=2829179566, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('0.0.0.0'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='de:ad:be:ef:c0:de', sname=b'', file=b'', options=OptionList([MessageType(code=53, length=1, data=b'\x03')])), ack=DHCPPacket(op='BOOTREPLY', htype='ETHERNET', hlen=6, hops=0, xid=2829179566, secs=0, flags=32768, ciaddr=IPv4Address('0.0.0.0'), yiaddr=IPv4Address('192.168.56.3'), siaddr=IPv4Address('0.0.0.0'), giaddr=IPv4Address('0.0.0.0'), chaddr='DE:AD:BE:EF:C0:DE', sname=b'', file=b'', options=OptionList([SubnetMask(code=1, length=4, data=b'\xff\xff\xff\x00'), Router(code=3, length=4, data=b'\n\x97\x01\x01'), DNSServer(code=6, length=4, data=b'\nh\x01\x08'), Hostname(code=12, length=22, data=b'dhcp.-192-168-56-3.com'), DomainName(code=15, length=14, data=b'example.com'), IPAddressLeaseTime(code=51, length=4, data=b'\x00\x01Q\x80'), MessageType(code=53, length=1, data=b'\x05'), ServerIdentifier(code=54, length=4, data=b'\xc0\xa88\x02'), RenewalTime(code=58, length=4, data=b'\x00\x00T`'), RebindingTime(code=59, length=4, data=b'\x00\x00\xa8\xc0'), End(code=255, length=0, data=b'')])), time=0.0032514659978915006, server=('192.168.56.2', 67))
```
