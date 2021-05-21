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

from concurrent import futures

import argparse
import grpc
import logging

from scion_grpc import hopfields_pb2_grpc, hopfields_pb2
from tofino import *

logger = logging.getLogger('scion_hopfields_registration_server')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

class HopFieldsRegistrationServiceServicer(
        hopfields_pb2_grpc.HopFieldsRegistrationServiceServicer):
    def __init__(self, grpc_addr = 'localhost:50052', client_id = 0, p4_name = "scion", dev = 0):
        self.dev_tgt = gc.Target(dev, pipe_id=0xFFFF)

        self.interface = gc.ClientInterface(grpc_addr,
                                            client_id=client_id,
                                            device_id=0)
        self.interface.bind_pipeline_config(p4_name)

        self.bfrt_info = self.interface.bfrt_info_get(p4_name)
        self.tbl_mac_verification = TblMacVerification(self.dev_tgt,
                                                       self.bfrt_info)

    def HopFieldsRegistration(self, request, context):
        try:
            logger.info("Received hop field registration request")
            logger.debug(request)
            logger.info("Add hop field to switch tables")
            logger.info("SegID: %x", request.segment_id)
            logger.info("MAC: %s", request.hop_field.mac.hex())

            self.tbl_mac_verification.entry_add_NoAction(
                request.segment_id, request.timestamp,
                request.hop_field.exp_time, request.hop_field.ingress,
                request.hop_field.egress, bytearray(request.hop_field.mac))
            # TODO include peer entries
            logger.info("Done")
        except gc.BfruntimeRpcException as e:
            for (_, se) in e.sub_errors_get():
                logger.error(se)
            raise e
        return hopfields_pb2.HopFieldsRegistrationResponse()

    def RemoveExpiredHopFields(self, request, context):
        try:
            logger.info("Checking for expired hop fields")
            self.tbl_mac_verification.remove_expired_entries()
            logger.info("Done removing expired hop fields")
        except gc.BfruntimeRpcException as e:
            for (_, se) in e.sub_errors_get():
                logger.error(se)
            raise e
        return hopfields_pb2.RemoveExpiredHopFieldsResponse()

def main():
    parser = argparse.ArgumentParser(description="Service to register hop fields and add them to the MAC verification tables at the Tofino switch")
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
        "--listen",
        "-l",
        default="[::]:10000",
        nargs="?",
        help="Address to listen on (default: [::]:10000)")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting hop fields registration service")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    servicer = HopFieldsRegistrationServiceServicer(grpc_addr=args.grpc_address, p4_name=args.program_name)
    hopfields_pb2_grpc.add_HopFieldsRegistrationServiceServicer_to_server(
        servicer, server)
    server.add_insecure_port(args.listen)

    try:
        server.start()
        logger.info("Running")
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.debug("Received KeyboardInterrupt")
    finally:
        servicer.interface.tear_down_stream()

if __name__ == "__main__":
    main()
