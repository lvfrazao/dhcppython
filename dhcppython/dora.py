import logging
import argparse
import json
from dhcppython import client, options, utils


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(threadName)s - %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler()],
    )

    help_texts = {
        "main": __doc__,
        "interface": "Interface to bind to and make DHCP requests",
        "mac_addr": "MAC address to use (default random)",
        "debug": "Print debug statements",
        "unicast": "Send DHCP packets over unicast to specified server",
        "server": "Server to send DHCP packets. Required for unicast and for relay use.",
        "relay": "Address to set the giaddr field to",
        "verbose": "Send random IP address",
        "options": "JSON body of options to include in requests",
        "port": "Port to send packets from on client machine",
        "target_port": "Port to send to on target machine",
        "target": "Given an IP address of a DHCP server, sends unicast requests",
    }
    parser = argparse.ArgumentParser(
        description=help_texts["main"], formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("-i", "--interface", type=str, help=help_texts["interface"])
    parser.add_argument("-a", "--mac_addr", type=str, default=utils.random_mac(), help=help_texts["mac_addr"])
    parser.add_argument("-d", "--debug", action="store_true", help=help_texts["debug"])
    parser.add_argument("-u", "--unicast", action="store_true", help=help_texts["unicast"])
    parser.add_argument("-s", "--server", type=str, default="255.255.255.255", help=help_texts["server"])
    parser.add_argument("-r", "--relay", type=str, help=help_texts["relay"])
    parser.add_argument('-v', '--verbose', action='count', default=0, help=help_texts["verbose"])
    parser.add_argument("-o", "--options", type=str, help=help_texts["options"])
    parser.add_argument("-p", "--port", type=int, default=68, help=help_texts["port"])
    parser.add_argument("--target_port", type=int, default=67, help=help_texts["target_port"])
    parser.add_argument("-@", type=str, dest="target", help=help_texts["target"])

    args = parser.parse_args()

    debug = args.debug
    if args.verbose > 2:
        debug = True

    if debug:
        print(args)

    if not debug:
        logging.disable(logging.DEBUG)

    mac_addr = args.mac_addr
    broadcast = not(args.unicast)
    server = args.server
    relay = args.relay
    verbosity = args.verbose

    if args.target:
        broadcast = False
        server = args.target
        relay = utils.get_ip_by_server(server)

    # Default options set
    opts = [
        options.options.short_value_to_object(61, {'hwtype': 1, 'hwaddr': mac_addr}),
        options.options.short_value_to_object(57, 1500),
        options.options.short_value_to_object(60, "android-dhcp-9"),
        options.options.short_value_to_object(12, "Galaxy-S9"),
        options.options.short_value_to_object(55, [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])
    ]
    if args.options:
        try:
            with open(args.options) as opt_file:
                opt_json = opt_file.read()
                opts_dict = json.loads(opt_json)
                opts = []
                for k,v in opts_dict.items():
                    opts.append(options.options.value_to_object({k: v}))
        except Exception as e:
            logging.error(f"Unable to parse JSON options file {args.option}: {e}")
            exit(1)
    options_list = options.OptionList(opts)
    if client_addr := options_list.by_code(61):
        mac_addr = client_addr.value["client_identifier"]["hwaddr"]

    if verbosity:
        print(f"{client.CLIENT_NAME} - v{client.CLIENT_VER} - {utils.cur_datetime()}")
    c = client.DHCPClient(args.interface, send_from_port=args.port, send_to_port=args.target_port)
    try:
        lease = c.get_lease(mac_addr, broadcast=broadcast, options_list=options_list, server=server, relay=relay, verbose=verbosity)
    except Exception as e:
        logging.debug(e)
        logging.error("Unable to obtain lease, run with -d to debug")
        if debug:
            raise
