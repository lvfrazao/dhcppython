import unittest
from dhcppython import options


class OptionsTestCases(unittest.TestCase):
    def setUp(self):
        self.options_client = options.options
        self.ip_array_list = ["192.168.56.0", "1.1.1.1", "255.255.255.0"]
        self.ip_array_bytes = b"\xc0\xa8\x38\x00" + b"\x01\x01\x01\x01" + b"\xff\xff\xff\x00"
        # Option 12
        self.string_str = "Galaxy-S9"
        self.string_bytes = b"\x47\x61\x6c\x61\x78\x79\x2d\x53\x39"
        self.opt12_bytes = b"\x0c\x09\x47\x61\x6c\x61\x78\x79\x2d\x53\x39"
        # Option 13
        self.uint16_int = 256
        self.uint16_bytes = b'\x01\x00'
        self.opt13_bytes = b'\x0d\x02\x01\x00'
        # Option 19
        self.bool_bool = True
        self.bool_bytes = b"\x01"
        self.opt19_bytes = b"\x13\x01\x01"
        # Option 21
        self.policy_filter_dict = [
            {"address": "1.1.1.1", "mask": "255.255.255.0"},
            {"address": "192.168.56.2", "mask": "255.255.255.0"}
        ]
        self.policy_filter_bytes = (
            b"\x01\x01\x01\x01" + b"\xff\xff\xff\x00" +
            b"\xc0\xa8\x38\x02" + b"\xff\xff\xff\x00"
        )
        self.opt21_bytes = b"\x15\x10" + self.policy_filter_bytes
        # Option 23
        self.uint8_int = 123
        self.uint8_bytes = b'\x7b'
        self.opt23_bytes = b'\x17\x01\x7b' 
        # Option 24
        self.uint32_int = 1234567
        self.uint32_bytes = b'\x00\x12\xd6\x87'
        self.opt24_bytes = b'\x18\x04' + self.uint32_bytes
        # Option 25
        self.uint16array_list = [12349, 23459, 34569, 45679]
        self.uint16array_bytes = (
            b'\x30\x3d' + b'\x5b\xa3' + b'\x87\x09' + b'\xb2\x6f'
        )
        self.opt25_bytes = b"\x19\x08" + self.uint16array_bytes
        # Option 33
        self.staticroute_list = [
            {"destination": "1.1.1.1", "router": "255.255.255.0"},
            {"destination": "192.168.56.2", "router": "255.255.255.0"}
        ]
        self.staticroute_bytes = (
            b"\x01\x01\x01\x01" + b"\xff\xff\xff\x00" +
            b"\xc0\xa8\x38\x02" + b"\xff\xff\xff\x00"
        )
        self.opt33_bytes = b"\x21\x10" + self.staticroute_bytes
        # Option 43
        self.bin_str = "0x0B 0x1C 0x01 0x02"
        self.bin_bytes = b"\x0b\x1c\x01\x02"
        self.opt43_bytes = b"\x2b\x04" + self.bin_bytes
        # Option 46
        self.netbios_node_str = "B-node"
        self.netbios_node_bytes = b"\x01"
        self.opt46_bytes = b"\x2e\x01" + self.netbios_node_bytes
        # Option 52
        self.overload_str = "'file' field is used to hold options"
        self.overload_bytes = b"\x01"
        self.opt52_bytes = b"\x34\x01" + self.overload_bytes
        # Option 53
        self.message_type_str = "DHCPREQUEST"
        self.message_type_bytes = b"\x03"
        self.opt53_bytes = b"\x35\x01" + self.message_type_bytes
        # Option 55
        self.parameter_request_list = [43, 53, 56, 74]
        self.parameter_request_bytes = b"\x2b\x35\x38\x4a"
        self.opt55_bytes = b"\x37\x04" + self.parameter_request_bytes
        # Option 61
        self.client_identifier_dict = {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}
        self.client_identifier_bytes = b'\x01\x8c\x45\x00\x1d\x48\x16'
        self.opt61_bytes = b'\x3d\x07' + self.client_identifier_bytes
        # Unknown Opt
        self.unknown_value = {'Unknown_250': "0x0A 0x12 0xDE 0xCA"}
        self.unknown_data = b'\x0a\x12\xde\xca'
        self.unknownopt_bytes = b'\xfa\x04' + self.unknown_data

    # Option 0 - Pad
    def test_pad_bytes_to_obj(self):
        self.assertEqual(self.options_client.bytes_to_object(b"\x00"), options.Pad(0, 0, b""))

    def test_pad_value_to_obj(self):
        self.assertEqual(self.options_client.value_to_object({"pad_option": ""}), options.Pad(0, 0, b""))

    def test_pad_value_to_bytes(self):
        self.assertEqual(self.options_client.value_to_bytes({"pad_option": ""}), b"\x00")
    
    def test_pad_obj_to_value(self):
        self.assertEqual(
            options.Pad(0, 0, b"").value,
            {"pad_option": ""}
        )

    # Option 255 - End
    def test_opt255_bytes_to_obj(self):
        self.assertEqual(self.options_client.bytes_to_object(b"\xff"), options.End(255, 0, b""))

    def test_opt255_value_to_obj(self):
        self.assertEqual(self.options_client.value_to_object({"end_option": ""}), options.End(255, 0, b""))

    def test_opt255_value_to_bytes(self):
        self.assertEqual(self.options_client.value_to_bytes({"end_option": ""}), b"\xff")

    def test_opt255_obj_to_value(self):
        self.assertEqual(
            options.End(255, 0, b"").value,
            {"end_option": ""}
        )

    # Option 1 - SubnetMask <- IPOption
    def test_opt1_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(b'\x01\x04\xff\xff\xff\x00'),
            options.SubnetMask(1, 4, b'\xff\xff\xff\x00')
        )

    def test_opt1_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"subnet_mask": "255.255.255.0"}),
            options.SubnetMask(1, 4, b'\xff\xff\xff\x00')
        )

    def test_opt1_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"subnet_mask": "255.255.255.0"}),
            b'\x01\x04\xff\xff\xff\x00'
        )

    def test_opt1_obj_to_value(self):
        self.assertEqual(
            options.SubnetMask(1, 4, b'\xff\xff\xff\x00').value,
            {"subnet_mask": "255.255.255.0"}
        )

    # Option 2 - TimeOffset <- int32Option
    def test_opt2_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(b'\x02\x04\x00\x00\x0e\x10'),
            options.TimeOffset(2, 4, b'\x00\x00\x0e\x10')
        )

    def test_opt2_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"time_offset_s": 3600}),
            options.TimeOffset(2, 4, b'\x00\x00\x0e\x10')
        )

    def test_opt2_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"time_offset_s": 3600}),
            b'\x02\x04\x00\x00\x0e\x10'
        )

    def test_opt2_obj_to_value(self):
        self.assertEqual(
            options.TimeOffset(2, 4, b'\x00\x00\x0e\x10').value,
            {"time_offset_s": 3600}
        )

    # Use -3600
    def test_opt2_bytes_to_obj2(self):
        self.assertEqual(
            self.options_client.bytes_to_object(b'\x02\x04\xff\xff\xf1\xf0'),
            options.TimeOffset(2, 4, b'\xff\xff\xf1\xf0')
        )

    def test_opt2_value_to_obj2(self):
        self.assertEqual(
            self.options_client.value_to_object({"time_offset_s": -3600}),
            options.TimeOffset(2, 4, b'\xff\xff\xf1\xf0')
        )

    def test_opt2_value_to_bytes2(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"time_offset_s": -3600}),
            b'\x02\x04\xff\xff\xf1\xf0'
        )

    # Option 3 - Router <- IPArrayOption
    def test_opt3_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(b'\x03\x0c' + self.ip_array_bytes),
            options.Router(3, 12, self.ip_array_bytes)
        )

    def test_opt3_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"routers": self.ip_array_list}),
            options.Router(3, 12, self.ip_array_bytes)
        )

    def test_opt3_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"routers": self.ip_array_list}),
            b'\x03\x0c' + self.ip_array_bytes
        )

    def test_opt3_obj_to_value(self):
        self.assertEqual(
            options.Router(3, 12, self.ip_array_bytes).value,
            {"routers": self.ip_array_list}
        )

    # Option 12 - Hostname <- StrOption
    def test_opt12_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt12_bytes),
            options.Hostname(12, 9, self.string_bytes)
        )

    def test_opt12_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"hostname": self.string_str}),
            options.Hostname(12, 9, self.string_bytes)
        )

    def test_opt12_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"hostname": self.string_str}),
            self.opt12_bytes
        )
    
    def test_opt12_obj_to_value(self):
        self.assertEqual(
            options.Hostname(12, 9, self.string_bytes).value,
            {"hostname": self.string_str}
        )

    # Option 13 - BootfileSize <- uint16Option
    def test_opt13_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt13_bytes),
            options.BootfileSize(13, 2, self.uint16_bytes)
        )

    def test_opt13_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"bootfile_size": self.uint16_int}),
            options.BootfileSize(13, 2, self.uint16_bytes)
        )

    def test_opt13_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"bootfile_size": self.uint16_int}),
            self.opt13_bytes
        )

    def test_opt13_obj_to_value(self):
        self.assertEqual(
            options.BootfileSize(13, 2, self.uint16_bytes).value,
            {"bootfile_size": self.uint16_int}
        )

    # Option 19 - IPForwarding <- BoolOption
    def test_opt19_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt19_bytes),
            options.IPForwarding(19, 1, self.bool_bytes)
        )

    def test_opt19_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"ip_forwarding": self.bool_bool}),
            options.IPForwarding(19, 1, self.bool_bytes)
        )

    def test_opt19_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"ip_forwarding": self.bool_bool}),
            self.opt19_bytes
        )

    def test_opt19_obj_to_value(self):
        self.assertEqual(
            options.IPForwarding(19, 1, self.bool_bytes).value,
            {"ip_forwarding": self.bool_bool}
        )

    # Option 21 - PolicyFilter <- Complex Option
    def test_opt21_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt21_bytes),
            options.PolicyFilter(21, 16, self.policy_filter_bytes)
        )

    def test_opt21_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"policy_filters": self.policy_filter_dict}),
            options.PolicyFilter(21, 16, self.policy_filter_bytes)
        )

    def test_opt21_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"policy_filters": self.policy_filter_dict}),
            self.opt21_bytes
        )

    def test_opt21_obj_to_value(self):
        self.assertEqual(
            options.PolicyFilter(21, 16, self.policy_filter_bytes).value,
            {"policy_filters": self.policy_filter_dict}
        )

    # Option 23 - IPTTL <- uint8Option
    def test_opt23_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt23_bytes),
            options.IPTTL(23, 1, self.uint8_bytes)
        )

    def test_opt23_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"default_ip_ttl": self.uint8_int}),
            options.IPTTL(23, 1, self.uint8_bytes)
        )

    def test_opt23_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"default_ip_ttl": self.uint8_int}),
            self.opt23_bytes
        )

    def test_opt23_obj_to_value(self):
        self.assertEqual(
            options.IPTTL(23, 1, self.uint8_bytes).value,
            {"default_ip_ttl": self.uint8_int}
        )

    # Option 24 - PathMTUAgingTimeout <- uint32Option
    def test_opt24_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt24_bytes),
            options.PathMTUAgingTimeout(24, 4, self.uint32_bytes)
        )

    def test_opt24_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"path_MTU_aging_timeout": self.uint32_int}),
            options.PathMTUAgingTimeout(24, 4, self.uint32_bytes)
        )

    def test_opt24_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"path_MTU_aging_timeout": self.uint32_int}),
            self.opt24_bytes
        )

    def test_opt24_obj_to_value(self):
        self.assertEqual(
            options.PathMTUAgingTimeout(24, 4, self.uint32_bytes).value,
            {"path_MTU_aging_timeout": self.uint32_int}
        )

    # Option 25 - PathMTUAgingTable <- uint16ArrayOption
    def test_opt25_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt25_bytes),
            options.PathMTUAgingTable(25, 8, self.uint16array_bytes)
        )

    def test_opt25_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"path_mtu_aging_table": self.uint16array_list}),
            options.PathMTUAgingTable(25, 8, self.uint16array_bytes)
        )

    def test_opt25_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"path_mtu_aging_table": self.uint16array_list}),
            self.opt25_bytes
        )

    def test_opt25_obj_to_value(self):
        self.assertEqual(
            options.PathMTUAgingTable(25, 8, self.uint16array_bytes).value,
            {"path_mtu_aging_table": self.uint16array_list}
        )

    # Option 33 - StaticRoute <- Complex
    def test_opt33_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt33_bytes),
            options.StaticRoute(33, 16, self.staticroute_bytes)
        )

    def test_opt33_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"static_routes": self.staticroute_list}),
            options.StaticRoute(33, 16, self.staticroute_bytes)
        )

    def test_opt33_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"static_routes": self.staticroute_list}),
            self.opt33_bytes
        )

    def test_opt33_obj_to_value(self):
        self.assertEqual(
            options.StaticRoute(33, 16, self.staticroute_bytes).value,
            {"static_routes": self.staticroute_list}
        )

    # Option 43 - VendorSpecificInformation <- BinOption
    def test_opt43_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt43_bytes),
            options.VendorSpecificInformation(43, 4, self.bin_bytes)
        )

    def test_opt43_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"vendor_specific_information": self.bin_str}),
            options.VendorSpecificInformation(43, 4, self.bin_bytes)
        )

    def test_opt43_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"vendor_specific_information": self.bin_str}),
            self.opt43_bytes
        )

    def test_opt43_obj_to_value(self):
        self.assertEqual(
            options.VendorSpecificInformation(43, 4, self.bin_bytes).value,
            {"vendor_specific_information": self.bin_str}
        )

    # Option 46 - NetbiosNodeType <- Complex
    def test_opt46_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt46_bytes),
            options.NetbiosNodeType(46, 1, self.netbios_node_bytes)
        )

    def test_opt46_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"netbios_node_type": self.netbios_node_str}),
            options.NetbiosNodeType(46, 1, self.netbios_node_bytes)
        )

    def test_opt46_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"netbios_node_type": self.netbios_node_str}),
            self.opt46_bytes
        )

    def test_opt46_obj_to_value(self):
        self.assertEqual(
            options.NetbiosNodeType(46, 1, self.netbios_node_bytes).value,
            {"netbios_node_type": self.netbios_node_str}
        )

    # Option 52 - Overload <- Complex
    def test_opt52_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt52_bytes),
            options.Overload(52, 1, self.overload_bytes)
        )

    def test_opt52_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"option_overload": self.overload_str}),
            options.Overload(52, 1, self.overload_bytes)
        )

    def test_opt52_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"option_overload": self.overload_str}),
            self.opt52_bytes
        )

    def test_opt52_obj_to_value(self):
        self.assertEqual(
            options.Overload(52, 1, self.overload_bytes).value,
            {"option_overload": self.overload_str}
        )

    # Option 53 - MessageType <- Complex
    def test_opt53_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt53_bytes),
            options.MessageType(53, 1, self.message_type_bytes)
        )

    def test_opt53_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"dhcp_message_type": self.message_type_str}),
            options.MessageType(53, 1, self.message_type_bytes)
        )

    def test_opt53_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"dhcp_message_type": self.message_type_str}),
            self.opt53_bytes
        )

    def test_opt53_obj_to_value(self):
        self.assertEqual(
            options.MessageType(53, 1, self.message_type_bytes).value,
            {"dhcp_message_type": self.message_type_str}
        )

    # Option 55 - ParameterRequestList <- uint8ArrayOption
    def test_opt55_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt55_bytes),
            options.ParameterRequestList(55, 4, self.parameter_request_bytes)
        )

    def test_opt55_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"parameter_request_list": self.parameter_request_list}),
            options.ParameterRequestList(55, 4, self.parameter_request_bytes)
        )

    def test_opt55_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"parameter_request_list": self.parameter_request_list}),
            self.opt55_bytes
        )

    def test_opt55_obj_to_value(self):
        self.assertEqual(
            options.ParameterRequestList(55, 4, self.parameter_request_bytes).value,
            {"parameter_request_list": self.parameter_request_list}
        )

    # Option 61 - ClientIdentifier <- Complex
    def test_opt61_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.opt61_bytes),
            options.ClientIdentifier(61, 7, self.client_identifier_bytes)
        )

    def test_opt61_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object({"client_identifier": self.client_identifier_dict}),
            options.ClientIdentifier(61, 7, self.client_identifier_bytes)
        )

    def test_opt61_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes({"client_identifier": self.client_identifier_dict}),
            self.opt61_bytes
        )

    def test_opt61_obj_to_value(self):
        self.assertEqual(
            options.ClientIdentifier(61, 7, self.client_identifier_bytes).value,
            {"client_identifier": self.client_identifier_dict}
        )

    # Unkown options <- UnknownOption
    def test_unknownopt_bytes_to_obj(self):
        self.assertEqual(
            self.options_client.bytes_to_object(self.unknownopt_bytes),
            options.UnknownOption(250, 4, self.unknown_data)
        )

    def test_unknownopt_value_to_obj(self):
        self.assertEqual(
            self.options_client.value_to_object(self.unknown_value),
            options.UnknownOption(250, 4, self.unknown_data)
        )

    def test_unknownopt_value_to_bytes(self):
        self.assertEqual(
            self.options_client.value_to_bytes(self.unknown_value),
            self.unknownopt_bytes
        )

    def test_unknownopt_obj_to_value(self):
        self.assertEqual(
            options.UnknownOption(250, 4, self.unknown_data).value,
            self.unknown_value
        )

if __name__ == "__main__":
    unittest.main()
