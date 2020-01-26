import unittest
from dhcppython import options


class OptionListTestCases(unittest.TestCase):
    def gen_optionslist(self):
        return options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
            ]
        )

    def test_OptionsList_append1(self):
        opt_list = self.gen_optionslist()
        opt_list.append(options.options.short_value_to_object(1, "255.255.255.0"))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
                options.options.short_value_to_object(1, "255.255.255.0")
            ]
            )
        )

    def test_OptionsList_append2(self):
        opt_list = self.gen_optionslist()
        opt_list.append(options.options.short_value_to_object(57, 2000))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_update_by_index1(self):
        opt_list = self.gen_optionslist()
        opt_list[1] = options.options.short_value_to_object(57, 2000)
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_update_by_index2(self):
        opt_list = self.gen_optionslist()
        opt_list[0] = options.options.short_value_to_object(57, 2000)
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_update_by_index3(self):
        opt_list = self.gen_optionslist()
        opt_list[3] = options.options.short_value_to_object(57, 2000)
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )
    
    def test_OptionList_insert1(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(1, options.options.short_value_to_object(57, 2000))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_insert2(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(0, options.options.short_value_to_object(57, 2000))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_insert3(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(3, options.options.short_value_to_object(57, 2000))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(57, 2000),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_insert4(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(0, options.options.short_value_to_object(1, "255.255.255.0"))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(1, "255.255.255.0"),
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_insert5(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(-1, options.options.short_value_to_object(1, "255.255.255.0"))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(1, "255.255.255.0"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_insert6(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(5, options.options.short_value_to_object(1, "255.255.255.0"))
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
                options.options.short_value_to_object(1, "255.255.255.0"),
            ]
            )
        )

    def test_OptionList_del1(self):
        opt_list = self.gen_optionslist()
        del opt_list[0]
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_del2(self):
        opt_list = self.gen_optionslist()
        del opt_list[-1]
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(60, "android-dhcp-9"),
                options.options.short_value_to_object(12, "Galaxy-S9"),
            ]
            )
        )

    def test_OptionList_del3(self):
        opt_list = self.gen_optionslist()
        del opt_list[2]
        self.assertEqual(
            opt_list,
            options.OptionList(
            [
                options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': "8c:45:00:1d:48:16"}),
                options.options.short_value_to_object(57, 1500),
                options.options.short_value_to_object(12, "Galaxy-S9"),
                options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
            ]
            )
        )

    def test_OptionList_len1(self):
        self.assertEqual(
            len(self.gen_optionslist()),
            5
        )

    def test_OptionList_len2(self):
        opt_list = self.gen_optionslist()
        opt_list.insert(5, options.options.short_value_to_object(1, "255.255.255.0"))
        opt_list.append(options.options.short_value_to_object(2, 3600))
        del opt_list[5]
        opt_list.append(options.options.short_value_to_object(1, "255.255.255.0"))
        del opt_list[5]

        self.assertEqual(
            len(opt_list),
            6
        )

    def test_OptionList_contains1(self):
        self.assertEqual(
            57 in self.gen_optionslist(),
            True
        )

    def test_OptionList_contains2(self):
        self.assertEqual(
            1 in self.gen_optionslist(),
            False
        )

    def test_OptionList_contains3(self):
        self.assertEqual(
            options.options.short_value_to_object(57, 1500) in self.gen_optionslist(),
            True
        )

    def test_OptionList_contains4(self):
        self.assertEqual(
            options.options.short_value_to_object(2, 3600) in self.gen_optionslist(),
            False
        )

    def test_OptionList_as_dict(self):
        self.assertEqual(
            self.gen_optionslist().as_dict(),
            {'client_identifier': {'hwtype': 1, 'hwaddr': '8C:45:00:1D:48:16'}, 'max_dhcp_message_size': 1500, 'vendor_class_identifier': 'android-dhcp-9', 'hostname': 'Galaxy-S9', 'parameter_request_list': [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]}
        )

    def test_OptionList_json(self):
        json_expected = (
            '{\n    "client_identifier": {\n        "hwtype": 1,\n        '
            '"hwaddr": "8C:45:00:1D:48:16"\n    },\n    "max_dhcp_message_'
            'size": 1500,\n    "vendor_class_identifier": "android-dhcp-9"'
            ',\n    "hostname": "Galaxy-S9",\n    "parameter_request_list"'
            ': [\n        1,\n        3,\n        6,\n        15,\n       '
            ' 26,\n        28,\n        51,\n        58,\n        59,\n   '
            '     43\n    ]\n}'
        )
        self.assertEqual(
            self.gen_optionslist().json,
            json_expected
        )


if __name__ == "__main__":
    unittest.main()
