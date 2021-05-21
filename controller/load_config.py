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
import ipaddress
import json
import logging

from tofino import *

logger = logging.getLogger('scion_load_config')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def load_configuration(config_file, grpc_address, p4_name, keep_mac_verification_table = False):
    configJSON = open(config_file)
    config = json.load(configJSON)
    
    grpc_addr = grpc_address
    client_id = 1
    p4_name = p4_name
    dev = 0
    dev_tgt = gc.Target(dev, pipe_id=0xFFFF)
    
    interface = gc.ClientInterface(grpc_addr, client_id=client_id, device_id=0)
    interface.bind_pipeline_config(p4_name)
    
    try:
        bfrt_info = interface.bfrt_info_get(p4_name)
    
        # Tables will be emptied and refilled with information from config file
    
        #TODO Be able to handle odd-length AS strings
        tbl_check_local = TblCheckLocal(dev_tgt, bfrt_info)
        tbl_check_local.clear()
    
        logger.info("Adding local ISD-AS info")
        tbl_check_local.entry_add_NoAction(config['localISD'],
                                           int(config['localAS'], 16))
    
        tbl_ingress_verification = TblIngressVerification(dev_tgt, bfrt_info)
        tbl_ingress_verification.clear()
    
        logger.info("Adding interfaces")
        for e in config['interfaces']:
            tbl_ingress_verification.entry_add_NoAction(e['interface'],
                                                        e['portId'])
    
        tbl_deliver_local = TblDeliverLocal(dev_tgt, bfrt_info)
        tbl_deliver_local.clear()
    
        logger.info("Adding local destinations")
        for e in config['localDestinations']:
            try:
                addr = ipaddress.ip_address(e['host'])
                mask = ipaddress.ip_address(e['netmask'])
                if isinstance(addr, ipaddress.IPv4Address):
                    tbl_deliver_local.entry_add_deliver_local_ipv4(
                        e['dt'], e['dl'], ipv4_to_bytes(e['host']), ipv4_to_bytes(e['netmask']),
                        e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
                elif isinstance(addr, ipaddress.IPv6Address):
                    tbl_deliver_local.entry_add_deliver_local_ipv6(
                        e['dt'], e['dl'], ipv6_to_bytes(e['host']), ipv6_to_bytes(e['netmask']),
                        e['egressPortId'], mac_to_bytes(e['dstMAC']), e['dstPort'])
            except ValueError:
                logger.info("Invalid address or netmask: %s / %s", e['host'], e['netmask'])
    
    
        logger.info("Adding local services")
        for e in config['localDestinationsService']:
            try:
                addr = ipaddress.ip_address(e['host'])
                if isinstance(addr, ipaddress.IPv4Address):
                    tbl_deliver_local.entry_add_deliver_local_service_ipv4(
                        e['dt'], e['dl'], e['host'], e['egressPortId'],
                        ipv4_to_bytes(e['dstIP']), mac_to_bytes(e['dstMAC']), e['dstPort'])
                elif isinstance(addr, ipaddress.IPv6Address):
                    tbl_deliver_local.entry_add_deliver_local_service_ipv6(
                        e['dt'], e['dl'], e['host'], e['egressPortId'],
                        ipv6_to_bytes(e['dstIP']), mac_to_bytes(e['dstMAC']), e['dstPort'])
            except ValueError:
                logger.info("Invalid address: %s", e['host'])
    
    
        tbl_forward = TblForward(dev_tgt, bfrt_info)
        tbl_forward.clear()
    
        logger.info("Adding fowarding info")
        for e in config['forwardLocal']:
            try:
                addr = ipaddress.ip_address(e['dstIP'])
                if isinstance(addr, ipaddress.IPv4Address):
                    tbl_forward.entry_add_forward_local_ipv4(e['egressInterface'], e['egressPortId'],
                                                  ipv4_to_bytes(e['dstIP']),
                                                  mac_to_bytes(e['dstMAC']), e['dstPort'])
                elif isinstance(addr, ipaddress.IPv6Address):
                    tbl_forward.entry_add_forward_local_ipv6(e['egressInterface'], e['egressPortId'],
                                                  ipv6_to_bytes(e['dstIP']),
                                                  mac_to_bytes(e['dstMAC']), e['dstPort'])
            except ValueError:
                logger.info("Invalid address: %s", e['dstIP'])
    
        for e in config['forwardRemote']:
            try:
                addr = ipaddress.ip_address(e['dstIP'])
                if isinstance(addr, ipaddress.IPv4Address):
                    tbl_forward.entry_add_forward_remote_ipv4(e['egressInterface'], e['egressPortId'],
                                                  ipv4_to_bytes(e['dstIP']),
                                                  mac_to_bytes(e['dstMAC']), e['dstPort'])
                elif isinstance(addr, ipaddress.IPv6Address):
                    tbl_forward.entry_add_forward_remote_ipv6(e['egressInterface'], e['egressPortId'],
                                                  ipv6_to_bytes(e['dstIP']),
                                                  mac_to_bytes(e['dstMAC']), e['dstPort'])
            except ValueError:
                logger.info("Invalid address: %s", e['dstIP'])
    
    
        tbl_set_local_source = TblSetLocalSource(dev_tgt, bfrt_info)
        tbl_set_local_source.clear()
    
        logger.info("Adding source information for ports")
        for e in config['localSource']:
            try:
                addr = ipaddress.ip_address(e['srcIP'])
                if isinstance(addr, ipaddress.IPv4Address):
                    tbl_set_local_source.entry_add_ipv4(e['egressPortId'],
                                               ipv4_to_bytes(e['srcIP']),
                                               mac_to_bytes(e['srcMAC']), e['srcPort'])
                elif isinstance(addr, ipaddress.IPv6Address):
                    tbl_set_local_source.entry_add_ipv6(e['egressPortId'],
                                               ipv6_to_bytes(e['srcIP']),
                                               mac_to_bytes(e['srcMAC']), e['srcPort'])
            except ValueError:
                logger.info("Invalid address: %s", e['srcIP'])
    
        if not keep_mac_verification_table:
            logger.info("Empty MAC table")
            tbl_mac_verification = TblMacVerification(dev_tgt, bfrt_info)
            tbl_mac_verification.clear()
    finally:
        interface.tear_down_stream()

def main():
    parser = argparse.ArgumentParser(description="Load configuration on the Tofino switch for the SCION implementation")
    parser.add_argument(
        "config_file",
        default="switch_config.json",
        nargs="?",
        help="Location of the configuration file (default: switch_config.json)")
    parser.add_argument(
        "--grpc_address",
        default="localhost:50052",
        nargs="?",
        help="GRPC address of the Tofino switch (default: localhost:50052)")
    parser.add_argument(
        "--program_name",
        "-p",
        default="scion",
        nargs="?",
        help="P4 program name (default: scion)")
    parser.add_argument(
        "--keep_mac_verification_table",
        action="store_true",
        help="Do not clear the MAC verification table")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    load_configuration(args.config_file, args.grpc_address, args.program_name, args.keep_mac_verification_table)

if __name__ == '__main__':
    main()
