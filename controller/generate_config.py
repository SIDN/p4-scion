# Copyright (c) 2021, SIDN Labs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import json

def as_to_str(asn):
    return "%04x%04x%04x" % (asn >> 32, asn >> 16 & 0xffff, asn & 0xffff)
  

def parse_as(asStr):
    (as0, as1, as2) = asStr.split(':', 2)
    return "%04x%04x%04x" % (int(as0, 16), int(as1, 16), int(as2, 16))

def parse_isdas(isdas):
    (isdStr, asStr) = isdas.split('-', 1)
    return (int(isdStr), parse_as(asStr))

def main():
    parser = argparse.ArgumentParser(description="Generate stub configuration for the SCION P4 implementation based on the topology.json")
    parser.add_argument(
        "-t",
        "--topology_file",
        default="topology.json",
        nargs="?",
        help="Location of the toplogy file (default: topology.json)")
    parser.add_argument(
        "-i",
        "--id",
        default="br1",
        nargs="?",
        help="Id of the border router for which the configuration should be generated (default: br1)")
    parser.add_argument(
        "-dp",
        "--dispatcher_port",
         type=int,
         default=30041,
         nargs="?",
         help="Port for the dispatcher (default: 30041)"
    )
    parser.add_argument(
        "--cpu_portid",
        type=int,
        default=64,
        nargs="?",
        help="PortId to forward packets to the CPU to (default: 64)"
    )
    parser.add_argument(
        "--recirculate_portid",
        type=int,
        default=68,
        nargs="?",
        help="PortId to recirculate packets (default: 68)"
    )
    args = parser.parse_args()

    topologyJSON = open(args.topology_file)
    topology = json.load(topologyJSON)

    switch_config = {}
    (switch_config['localISD'], switch_config['localAS']) = parse_isdas(topology['isd_as'])

    switch_config['interfaces'] = []
    # Recirculate when switching between segments
    # TODO Make recirculation port configurable (might also change per pipe)
    switch_config['interfaces'].append({"interface": 0, "portId": args.recirculate_portid})
    # Local network
    switch_config['interfaces'].append({"interface": 0, "portId": "<PORTID_LOCAL>"})

    switch_config['localDestinations'] = []
    # Add example destinations
    switch_config['localDestinations'].append({ "dl": 0, "dt": 0, "host": "<LOCAL_DST_IPV4_ADDRESS>", "netmask": "<LOCAL_DST_IPV4_NETMASK>", "egressPortId": "<PORTID_LOCAL>", "dstMAC": "<LOCAL_DST_IPV4_MAC>", "dstPort": args.dispatcher_port, "comment": "This is an example IPv4 local destination"})
    switch_config['localDestinations'].append({ "dl": 3, "dt": 0, "host": "<LOCAL_DST_IPV6_ADDRESS>", "netmask": "<LOCAL_DST_IPV6_NETMASK>", "egressPortId": "<PORTID_LOCAL>", "dstMAC": "<LOCAL_DST_IPV6_MAC>", "dstPort": args.dispatcher_port, "comment": "This is an example IPv6 local destination"})

    switch_config['localDestinationsService'] = []

    control_service = list(topology['control_service'].values())
    (ip, _) = control_service[0]['addr'].split(':', 1)
    # We use the default port of the dispatcher
    switch_config['localDestinationsService'].append({"dl": 0, "dt": 1, "host": 0x10000, "egressPortId": "<PORTID_LOCAL>", "dstIP": ip, "dstMAC": "<MAC_CONTROL_SERVICE>", "dstPort": args.dispatcher_port})

    discovery_service = list(topology['discovery_service'].values())
    (ip, _) = discovery_service[0]['addr'].split(':', 1)
    # We use the default port of the dispatcher
    switch_config['localDestinationsService'].append({"dl": 0, "dt": 1, "host": 0x20000, "egressPortId": "<PORTID_LOCAL>", "dstIP": ip, "dstMAC": "<MAC_DISCOVERY_SERVICE>", "dstPort": args.dispatcher_port})

    switch_config['localSource'] = []
    # Source for packets to CPU
    switch_config['localSource'].append({"egressPortId": args.cpu_portid, "srcIP": "0.0.0.0", "srcMAC": "00:00:00:00:00:00", "srcPort": 0})
    # Source for packets when recirculating
    switch_config['localSource'].append({"egressPortId": args.recirculate_portid, "srcIP": "0.0.0.0", "srcMAC": "00:00:00:00:00:00", "srcPort": 0})
    # Source for local delivery
    (localIP, localPort) = topology['border_routers'][args.id]['internal_addr'].split(':', 1)
    switch_config['localSource'].append({"egressPortId": "<PORTID_LOCAL>", "srcIP": localIP, "srcMAC": "<MAC_PORTID_LOCAL>", "srcPort": localPort})

    # forwardLocal is used when there are multiple border routers and the egress interface is at another border router
    switch_config['forwardLocal'] = []
    # forwardRemote is used when the egress interface is at the current border router
    switch_config['forwardRemote'] = []

    for intf_id in topology['border_routers'][args.id]["interfaces"]:
        intf_data = topology['border_routers'][args.id]["interfaces"][intf_id]

        switch_config['interfaces'].append({"interface": intf_id, "portId": "<PORTID_AS_%s>" % intf_data['isd_as']})

        (localIP, localPort) = intf_data['underlay']['public'].split(':', 1)
        switch_config['localSource'].append({"egressPortId": "<PORTID_AS_%s>" % intf_data['isd_as'], "srcIP": localIP, "srcMAC": "<MAC_PORTID_AS_%s>" % intf_data['isd_as'], "srcPort": int(localPort)})     

        (remoteIP, remotePort) = intf_data['underlay']['remote'].split(':', 1)
        switch_config['forwardRemote'].append({'egressInterface': intf_id, 'egressPortId': "<PORTID_AS_%s>", "dstIP": remoteIP, "dstMAC": "<MAC_REMOTE_AS_%s>" % intf_data['isd_as'], "dstPort": int(remotePort)})

        if intf_data['link_to'] == "PARENT":
            # Allow packets that were initially received from an upstream AS and processed by the CPU (in case of a one-hop path)
            switch_config['interfaces'].append({"interface": intf_id, "portId": args.cpu_portid})
            # Allow the use of partial down-segments sent from the local network
            switch_config['interfaces'].append({"interface": intf_id, "portId": "<PORTID_LOCAL>"})
            # Allow switching to a partial down-segment (e.g. when an up- and down-segment intersect before reaching the core)
            switch_config['interfaces'].append({"interface": intf_id, "portId": args.recirculate_portid})

    for br in topology['border_routers']:
        if br != args.id:
            br_data = topology['border_routers'][br]
            (brIP, brPort) = br_data['internal_addr'].split(':', 1)

            switch_config['localSource'].append({"egressPortId": "<PORTID_BR_%s>" % br, "srcIP": "<IP_PORTID_BR_%s>" % br, "srcMAC": "<MAC_PORTID_BR_%s>" % br, "srcPort": "<PORT_PORTID_BR_%s>" % br})

            for intf_id in br_data["interfaces"]:
                intf_data = br_data["interfaces"][intf_id]

                switch_config['interfaces'].append({"interface": intf_id, "portId": "<PORTID_BR_%s>" % br})
                switch_config['forwardLocal'].append({'egressInterface': intf_id, 'egressPortId': "<PORTID_LOCAL>", "dstIP": brIP, "dstMAC": "<MAC_REMOTE_BR_%s>" % br, "dstPort": int(brPort)})
                if intf_data['link_to'] == "PARENT":
                    # Allow the use of partial down-segments sent from the local network
                    switch_config['interfaces'].append({"interface": intf_id, "portId": "<PORTID_LOCAL>"})
                    # Allow switching to a partial down-segment (e.g. when an up- and down-segment intersect before reaching the core)
                    switch_config['interfaces'].append({"interface": intf_id, "portId": args.recirculate_portid})

    print(json.dumps(switch_config, indent=4))

if __name__ == '__main__':
    main()



