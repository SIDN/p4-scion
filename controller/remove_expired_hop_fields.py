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
import time
import logging

import grpc
from scion_grpc import hopfields_pb2_grpc
from scion_grpc import hopfields_pb2

logger = logging.getLogger('scion_remove_expired_hop_fields')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def main():
    parser = argparse.ArgumentParser(description="Trigger process to remove expired hop fields")
    parser.add_argument(
        "--grpc_address",
        default="localhost:10000",
        nargs="?",
        help="address of the GRPC server to register the generated hop fields (default: localhost:10000)")
    parser.add_argument(
        "-c",
        "--count",
        default=-1,
        type=int,
        nargs="?",
        help="how often should we remove the expired hop fields, -1 for unlimited (default: -1)")
    parser.add_argument(
        "-i",
        "--interval",
        default=10,
        type=int,
        nargs="?",
        help="how many seconds should we wait in between removing expired hop fields (default: 10)")
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable output of debug info")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    channel = grpc.insecure_channel(args.grpc_address)
    stub = hopfields_pb2_grpc.HopFieldsRegistrationServiceStub(channel)

    c = args.count
    while c != 0:
        logger.debug("Remove expired hop fields")
        try:
            result = stub.RemoveExpiredHopFields(hopfields_pb2.RemoveExpiredHopFieldsRequest())
            logger.debug(result)
        except Exception as e:
            logger.error("Error: %s" % e)
        c = c - 1
        if c == 0:
            break
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
