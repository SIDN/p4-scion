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

from scapy.all import sniff, bind_layers, Ether, sendp
from scion_scapy.scion import SCION, SCIONOneHopPath

import argparse
import binascii
import json
import logging

import grpc
from scion_grpc import hopfields_pb2_grpc
from scion_grpc import hopfields_pb2

from scion_crypto import get_key, compute_mac

# Be aware of consDir when providing input for MAC!
# consDir == 0, then XOR segID with first bytes of MAC to get segID input for MAC

logger = logging.getLogger('scion_onehope_processor')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

class OneHopProcessor:
    def __init__(self, key, interface, grpc_address, interface_mapping):
        self.key = key
        self.interface = interface
        self.grpc_address = grpc_address

        self.interface_mapping = {}
        for im in interface_mapping:
            self.interface_mapping[im['portId']] = im['interface']

        self.channel = grpc.insecure_channel(self.grpc_address)
        self.stub = hopfields_pb2_grpc.HopFieldsRegistrationServiceStub(self.channel)

    def packet_callback(self, pkt):
        if SCION in pkt:
            logger.debug("SCION packet")
            path = pkt[SCION].path
            if isinstance(path, SCIONOneHopPath):
                new_pkt = pkt[Ether].payload
                expTime = 63 # TODO Make configurable?
                mac = binascii.unhexlify(str(pkt[Ether].src).replace(':', ''))
                # TODO The next might fail, in which case we received an one-hop path from an unexpected port
                ingress = self.interface_mapping[int.from_bytes(mac, byteorder='big')]
                logger.debug("Extracted ingress: %d" % ingress)
                cmac = compute_mac(self.key, path.infofield.segID, path.infofield.timestamp, expTime, ingress, 0)
                new_pkt[SCION].path.hopfield1.expTime = expTime
                new_pkt[SCION].path.hopfield1.consIngress = ingress
                new_pkt[SCION].path.hopfield1.consEgress = 0
                new_pkt[SCION].path.hopfield1.mac = int.from_bytes(cmac.digest()[0:6], byteorder='big')
    
                logger.info("Register new MAC %x" % new_pkt[SCION].path.hopfield1.mac)
                try:
                  result = self.stub.HopFieldsRegistration(hopfields_pb2.HopFieldsRegistrationRequest(
                                                           timestamp=path.infofield.timestamp,
                                                           segment_id=path.infofield.segID,
    #                                                      segment_id=int.from_bytes(cmac.digest()[0:2], byteorder='big') ^ pkt[SCION].path.infofield.segID,
                                                           hop_field=hopfields_pb2.HopField(ingress=ingress, egress=0, exp_time=expTime, mac=cmac.digest()[0:6])))
                  logger.debug(result)
                except Exception as e:
                  logger.error("Error registering MAC: %s" % e)
                sendp(new_pkt, iface=self.interface)

    def run(self):
        logger.info("Start sniffing on interface %s" % self.interface)
        sniff(prn=self.packet_callback, iface=self.interface, filter="inbound", store=0)

def main():
    parser = argparse.ArgumentParser(description="Service to process one-hop paths: compute and register missing hop field")
    parser.add_argument(
        "-k",
        "--key_file",
        default="master0.key",
        help="key file containing the master key for the generation of hop field MACs (default: master0.key)"
    )
    parser.add_argument(
        "-m",
        "--mapping_config",
        default="interface_mapping.json",
        help="config file containing the maapping between portIds and SCION interfacesi (default: inteface_mapping.json)"
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="veth251",
        nargs="?",
        help="interface to listen on for SCION packets and send processed packets on (default: veth251)")
    parser.add_argument(
        "--grpc_address",
        default="localhost:10000",
        nargs="?",
        help="address of the GRPC server to register the generated hop fields (default: localhost:10000)")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    master0_file = open(args.key_file, 'r')
    master0 = master0_file.read()
    key = get_key(master0)

    mappingJSON = open(args.mapping_config)
    mapping = json.load(mappingJSON)

    processor = OneHopProcessor(key, args.interface, args.grpc_address, mapping)
    processor.run()

bind_layers(Ether, Ether, type = 0x5C10)

if __name__ == "__main__":
    main()
