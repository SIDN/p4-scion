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

import bfrt_grpc.client as gc

from bfrt_grpc.client import mac_to_bytes, ipv4_to_bytes, ipv6_to_bytes, bytes_to_int

import time
import binascii

class Tbl(object):
    def __init__(self, dev_tgt, bfrt_info, tbl_name):
        self.dev_tgt = dev_tgt
        self.bfrt_info = bfrt_info
        self.tbl = bfrt_info.table_get(tbl_name)

    def clear(self):
        self.tbl.entry_del(self.dev_tgt)

    def get_entries(self):
        # We use empty flags as the default value ({"from_hw": True}) results in an exception on the model
        return self.tbl.entry_get(self.dev_tgt, flags={})

    def entry_del(self, key):
        return self.tbl.entry_del(self.dev_tgt, [key]) 

class TblMacVerification(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblMacVerification,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_mac_verification")

    def make_key(self, segId, timestamp, expTime, inIf, egIf, mac):
        return self.tbl.make_key([
            gc.KeyTuple('meta.segId', segId),
            gc.KeyTuple('meta.timestamp', timestamp),
            gc.KeyTuple('hdr.scion_hop_field_0.expTime', expTime),
            gc.KeyTuple('hdr.scion_hop_field_0.inIf', inIf),
            gc.KeyTuple('hdr.scion_hop_field_0.egIf', egIf),
            gc.KeyTuple('hdr.scion_hop_field_0.mac', mac),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, segId, timestamp, expTime, inIf, egIf, mac):
        key = self.make_key(segId, timestamp, expTime, inIf, egIf, mac)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_del(self, segId, timestamp, expTime, inIf, egIf, mac):
        key = self.make_key(segId, timestamp, expTime, inIf, egIf, mac)
        return super(TblMacVerification, self).entry_del(self.dev_tgt, key)

    def remove_expired_entries(self, currentTime = None):
        if currentTime == None:
            currentTime = int(time.time())
        for (_, k) in self.get_entries():
            timestamp = int(binascii.hexlify(k['meta.timestamp'].value), 16)
            expTime = int(
                binascii.hexlify(k['hdr.scion_hop_field_0.expTime'].value), 16)
            expire = timestamp + (1 + expTime) * 337.5
            if expire < currentTime:
                print("Entry expired")
                super(TblMacVerification, self).entry_del(k)
            else:
                print("Entry still valid for", int(expire - currentTime),
                      "seconds")

class TblIngressVerification(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblIngressVerification,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_ingress_verification")

    def make_key(self, hfIngress, ingressPort):
        return self.tbl.make_key([
            gc.KeyTuple('meta.ingress', hfIngress),
            gc.KeyTuple('ig_intr_md.ingress_port', ingressPort),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, hfIngress, ingressPort):
        key = self.make_key(hfIngress, ingressPort)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblCheckLocal(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblCheckLocal, self).__init__(dev_tgt, bfrt_info,
                                            "ScionIngressControl.tbl_check_local")

    def make_key(self, isd, asn):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_addr_common.dstISD', isd),
            gc.KeyTuple('hdr.scion_addr_common.dstAS', asn),
        ])

    def make_data_NoAction(self):
        return self.tbl.make_data([], "NoAction")

    def entry_add_NoAction(self, isd, asn):
        key = self.make_key(isd, asn)
        data = self.make_data_NoAction()
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblDeliverLocal(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblDeliverLocal, self).__init__(dev_tgt, bfrt_info,
                                              "ScionIngressControl.tbl_deliver_local")
    def make_key(self, destType, destLen, destIpv4, destIpv4Mask, destIpv6, destIpv6Mask):
        return self.tbl.make_key([
            gc.KeyTuple('hdr.scion_common.dl', destLen),
            gc.KeyTuple('hdr.scion_common.dt', destType),
            gc.KeyTuple('hdr.scion_addr_dst_host_32.host', destIpv4, destIpv4Mask),
            gc.KeyTuple('hdr.scion_addr_dst_host_128.host', destIpv6, destIpv6Mask),
        ])

    def make_data_deliver_local_ipv6(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv6")

    def entry_add_deliver_local_ipv6(self, destType, destLen, dest, destMask,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, 0, 0, dest, destMask)
        data = self.make_data_deliver_local_ipv6(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


    def make_data_deliver_local_ipv4(self, port, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_ipv4")

    def entry_add_deliver_local_ipv4(self, destType, destLen, dest, destMask,
                                     port, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, destMask, 0, 0)
        data = self.make_data_deliver_local_ipv4(port, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_deliver_local_service_ipv4(self, port, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_service_ipv4")

    def entry_add_deliver_local_service_ipv4(self, destType, destLen, dest, port,
                                        dstIP, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, 0xFFFFFFFF, 0, 0)
        data = self.make_data_deliver_local_service_ipv4(port, dstIP, dstMAC,
                                                    dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_deliver_local_service_ipv6(self, port, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', port),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "deliver_local_service_ipv6")

    def entry_add_deliver_local_service_ipv6(self, destType, destLen, dest, port,
                                        dstIP, dstMAC, dstPort):
        key = self.make_key(destType, destLen, dest, 0xFFFFFFFF, 0, 0)
        data = self.make_data_deliver_local_service_ipv6(port, dstIP, dstMAC,
                                                    dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblForward(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblForward, self).__init__(dev_tgt, bfrt_info,
                                         "ScionIngressControl.tbl_forward")

    def make_key(self, hfEgress):
        return self.tbl.make_key([
            gc.KeyTuple('meta.egress', hfEgress),
        ])

    def make_data_forward_local_ipv4(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_local_ipv4")

    def make_data_forward_remote_ipv4(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_remote_ipv4")

    def entry_add_forward_local_ipv4(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_local_ipv4(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_add_forward_remote_ipv4(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_remote_ipv4(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_forward_local_ipv6(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_local_ipv6")

    def make_data_forward_remote_ipv6(self, egressPort, dstIP, dstMAC, dstPort):
        return self.tbl.make_data([
            gc.DataTuple('port', egressPort),
            gc.DataTuple('dstIP', dstIP),
            gc.DataTuple('dstMAC', dstMAC),
            gc.DataTuple('dstPort', dstPort),
        ], "forward_remote_ipv6")

    def entry_add_forward_local_ipv6(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_local_ipv6(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def entry_add_forward_remote_ipv6(self, hfEgress, egressPort, dstIP, dstMAC, dstPort):
        key = self.make_key(hfEgress)
        data = self.make_data_forward_remote_ipv6(egressPort, dstIP, dstMAC, dstPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])


class TblSetLocalSource(Tbl):
    def __init__(self, dev_tgt, bfrt_info):
        super(TblSetLocalSource,
              self).__init__(dev_tgt, bfrt_info,
                             "ScionIngressControl.tbl_set_local_source")

    def make_key(self, egressPort):
        return self.tbl.make_key([
            gc.KeyTuple('ig_tm_md.ucast_egress_port', egressPort),
        ])

    def make_data_set_local_source_ipv4(self, srcIp, srcMAC, srcPort):
        return self.tbl.make_data([
            gc.DataTuple('srcIp', srcIp),
            gc.DataTuple('srcMAC', srcMAC),
            gc.DataTuple('srcPort', srcPort),
        ], "set_local_source_ipv4")

    def entry_add_ipv4(self, egressPort, srcIp, srcMAC, srcPort):
        key = self.make_key(egressPort)
        data = self.make_data_set_local_source_ipv4(srcIp, srcMAC, srcPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])

    def make_data_set_local_source_ipv6(self, srcIp, srcMAC, srcPort):
        return self.tbl.make_data([
            gc.DataTuple('srcIp', srcIp),
            gc.DataTuple('srcMAC', srcMAC),
            gc.DataTuple('srcPort', srcPort),
        ], "set_local_source_ipv6")

    def entry_add_ipv6(self, egressPort, srcIp, srcMAC, srcPort):
        key = self.make_key(egressPort)
        data = self.make_data_set_local_source_ipv6(srcIp, srcMAC, srcPort)
        return self.tbl.entry_add(self.dev_tgt, [key], [data])
