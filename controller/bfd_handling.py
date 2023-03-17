# Copyright (c) 2023, NetSys Lab, Otto-von-Guericke-University Magdeburg
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

from scapy.all import sniff, bind_layers, Ether, IP, UDP, sendp
from scapy.contrib.bfd import BFD
from scion_scapy.scion import SCION, SCIONOneHopPath, InfoField, HopField
from scion_crypto import get_key, compute_mac
from multiprocessing import Process, Lock, Pool, Value
from tofino import *

import argparse
import time
import random
import binascii
import ipaddress
import json
import socket
import logging

# Definitions:
BFD_ADMIN_DOWN = 0
BFD_DOWN = 1
BFD_INIT = 2
BFD_UP = 3

logger = logging.getLogger('scion_onehope_processor')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

# Class for a single BFD session
class BfdSession:
    def __init__(self, key, interface, srcMac, dstMac, srcIp, dstIp, additionalIfs, srcUdpPort, dstUdpPort,
            srcIsd, dstIsd, srcAs, dstAs, myDiscrimi, egIfId):
        # Set BFD packet fields
        self.key = key
        self.interface = interface
        self.state = Value('i', BFD_DOWN)
        self.stateMutex = Lock()
        self.srcMAC = srcMac
        self.dstMAC = dstMac
        self.srcIP = srcIp
        self.dstIP = dstIp
        self.additionalIFs = additionalIfs
        self.srcUDPPort = srcUdpPort
        self.dstUDPPort = dstUdpPort
        self.srcISD = srcIsd
        self.dstISD = dstIsd
        self.srcAS = srcAs
        self.dstAS = dstAs
        self.egressInterface = egIfId
        self.myDiscrimi = myDiscrimi
        self.yourDiscrimi = Value('i', 0)
        # Initial value fro minimum Tx interval is 1 second, it is negotiated during the BFD session.
        self.minTx = Value('i', 1000000)
        self.downInterval = 1000000
        # Normally required Rx interval is set to 200000 in SCION. Can be changed to decrease the BFD interval.
        self.reqRx = 1000000
        self.timeMutex = Lock()
        self.timeout = Value('d', time.time() + 3)

    # Send a BFD packet out
    def sendPacket(self):
        # Create SCION BFD packet with scapy
        pkt = None
        with self.timeMutex:
            with self.stateMutex:
                yourDiscriminator = self.yourDiscrimi.value
                if self.state.value <= BFD_DOWN:
                    yourDiscriminator = 0
                pkt = Ether(src=self.srcMAC, dst=self.dstMAC)/ \
                      IP(src=self.srcIP, dst=self.dstIP, ttl=64)/ \
                      UDP(sport=self.srcUDPPort, dport=self.dstUDPPort)/ \
                      SCION(qos=0xb8, flowID=0x0dead, nextHdr=0xCB, payloadLen=24,
                            dstISD=self.dstISD, dstAS=self.dstAS,
                            srcISD=self.srcISD, srcAS=self.srcAS,
                            dstAddress=socket.inet_aton(self.dstIP), srcAddress=socket.inet_aton(self.srcIP))/ \
                      BFD(sta=self.state.value,
                          my_discriminator=self.myDiscrimi, your_discriminator=yourDiscriminator,
                          min_tx_interval=self.minTx.value, min_rx_interval=self.reqRx, echo_rx_interval=0)
            if self.dstAS == self.srcAS:
                # Internal session - SCION Empty Path
                pkt[SCION].hdrLen = 9
                pkt[SCION].pathType = 0
                pkt[SCION].path = ""
            else:
                # External session - SCION OneHop Path
                pkt[SCION].hdrLen = 17
                pkt[SCION].pathType = 2
                pkt[SCION].path = SCIONOneHopPath()
                pkt[SCION].path.infofield = InfoField()
                pkt[SCION].path.hopfield0 = HopField()
                pkt[SCION].path.hopfield1 = HopField()
                
                pkt[SCION].path.infofield.flags = 1
                timestamp = int(time.time())
                pkt[SCION].path.infofield.timestamp = timestamp
                pkt[SCION].path.hopfield0.expTime = 63
                pkt[SCION].path.hopfield0.consEgress = self.egressInterface
                cmac = compute_mac(self.key, 0, timestamp, 63, 0, 0)
                pkt[SCION].path.hopfield0.mac = int.from_bytes(cmac.digest()[0:6], byteorder='big')
            # Send packet
            sendp(pkt, iface=self.interface, verbose=0)
    
    # Reset the timeout for incoming packets
    def setLastRxTime(self, timeout):
        self.timeout.value = time.time() + timeout

    # Getter for the actual state of the BFD session
    def getState(self):
        return self.state.value

    # Setter for the actual state of the BFD session
    def setState(self, state=int):
        with self.stateMutex:
            # Check, whether the received state is valid
            if state >= BFD_ADMIN_DOWN and state <= BFD_UP:
                self.state.value = state
                return self.state.value
        return -1

    # Getter for the "yourDiscriminator" value
    def getYourDiscrimi(self):
        return self.yourDiscrimi.value

    # Setter for the "yourDiscriminator" value
    def setYourDiscrimi(self, yourDiscrimi):
        # Check, that the parameter is non-zero and unknown
        if self.yourDiscrimi.value != yourDiscrimi and yourDiscrimi != 0:
            self.yourDiscrimi.value = yourDiscrimi
            return 1
        if self.yourDiscrimi.value == yourDiscrimi:
            return 0
        return -1

    # Getter for actual used minimum Tx interval
    def getTxInterval(self):
        return self.minTx.value

    # Setter for actual used minimum Tx interval
    def setTxInterval(self, yourMinRx):
        with self.timeMutex:
            # Check, if the Session is able to handle messages in this interval or not
            if yourMinRx < self.reqRx:
                # If the interval is too fast, use the required Rx interval instead...
                self.minTx.value = self.reqRx
                return 0
            else:
                # ...otherwise use the newly received value
                self.minTx.value = yourMinRx
                return 1

    # Down state (and Admin-Down as well) of the session
    def down(self):
        i = 0
        while self.state.value == BFD_DOWN or self.state.value == BFD_ADMIN_DOWN:
            # Measure the time needed for the function
            startTime = time.time()
            
            # Send a packet every fifth time the function is called
            if i == 0:
                self.sendPacket()
            i = (i + 1) % 5
            
            # Sleep for 1/5 of the BFD interval in down state minus jitter. This is done to react faster on state changes.
            with self.timeMutex:
                sleepTime = self.downInterval / 5 - (self.downInterval / 5 * 0.25 * random.random())
            time.sleep(max(sleepTime / 1000000 - (time.time() - startTime), 0))

    # Up state (and Init as well) of the session
    def up(self):
        initcnt = 0
        while self.state.value == BFD_UP or self.state.value == BFD_INIT:
            # Measure the time needed for the function
            startTime = time.time()
            
            # If 10 BFD init frames were sent without the peer staying in state down,
            # set session to state down to reset the session
            with self.stateMutex:
                if self.state.value == BFD_INIT:
                    if initcnt > 9:
                        self.state.value = BFD_DOWN
                        with self.timeMutex:
                            self.minTx.value = 1000000
                    initcnt = initcnt + 1
            
            # If the peer does not send a BFD packet before the timeout is reached, set session to down
            if time.time() > self.timeout.value:
                with self.stateMutex:
                    self.state.value = BFD_DOWN
                with self.timeMutex:
                    self.minTx.value = 1000000
                return
            
            # Send a BFD packet
            self.sendPacket()
            
            # Sleep for the negotiated amount of time minus jitter (and minus the time needed for this function)
            with self.timeMutex:
                sleepTime = self.minTx.value - (self.minTx.value * 0.25 * random.random())
            time.sleep(max(sleepTime / 1000000 - (time.time() - startTime), 0))

    # Run this session
    def run(self):
        while True:
            # Apply either the down session or the up session algorithm
            if self.state.value == BFD_DOWN or self.state.value == BFD_ADMIN_DOWN:
                self.down()
            if self.state.value == BFD_UP or self.state.value == BFD_INIT:
                self.up()

# The BFD handler registers all BFD sessions needed for the border router
class BfdHandler:
    def __init__(self, configFile, key, interface):
        self.interface = interface
        # Read config from file
        configJSON = open(configFile)
        config = json.load(configJSON)
        configJSON.close()
        # Read fields from config
        self.hostAS = int('0x' + config['localAS'], 16)
        self.hostISD = config['localISD']
        self.egressInterfaces = []
        self.egressPorts = []
        self.dstIPs = []
        additionalInterfaces = []
        dstMACs = []
        self.dstUDPPorts = []
        dstISDs = []
        dstASes = []
        srcIPs = {}
        srcMACs = {}
        srcUDPPorts = {}
        self.bfdSessions = []
        self.bfdProcesses = []
        for element in config['remoteDestinations']:
            self.egressInterfaces.append(element['egressInterface'])
            self.egressPorts.append(element['egressPortId'])
            self.dstIPs.append(element['dstIP'])
            additionalInterfaces.append([])
            dstMACs.append(element['dstMAC'])
            self.dstUDPPorts.append(element['dstPort'])
            dstISDs.append(element['dstISD'])
            dstASes.append(int('0x' + element['dstAS'], 16))
        for element in config['localDestinations']:
            self.egressInterfaces.append(element['egressInterface'])
            self.egressPorts.append(element['egressPortId'])
            self.dstIPs.append(element['dstIP'])
            additionalInterfaces.append([])
            for entry in config['localInterfaces']:
                if element['dstIP'] == entry['dstIP']:
                    additionalInterfaces[-1].append(entry['egressInterface'])
            dstMACs.append(element['dstMAC'])
            self.dstUDPPorts.append(element['dstPort'])
            dstISDs.append(self.hostISD)
            dstASes.append(self.hostAS)
        for element in config['localSource']:
            srcIPs[element['egressPortId']] = element['srcIP']
            srcMACs[element['egressPortId']] = element['srcMAC']
            srcUDPPorts[element['egressPortId']] = element['srcPort']
        # Create BFD Sessions for each connected SCION reouter
        for i in range(len(self.egressInterfaces)):
            self.bfdSessions.append(BfdSession(key, self.interface, srcMACs[self.egressPorts[i]], dstMACs[i],
                                    srcIPs[self.egressPorts[i]], self.dstIPs[i], additionalInterfaces[i],
                                    srcUDPPorts[self.egressPorts[i]], self.dstUDPPorts[i],
                                    self.hostISD, dstISDs[i], self.hostAS, dstASes[i],
                                    random.randint(1, (2**32) - 1), self.egressInterfaces[i]))
            logger.info("Created BFD Session for: %x-%x on %s:%s", dstISDs[i], dstASes[i], self.dstIPs[i], self.dstUDPPorts[i])
            
    # Set a session to a new state
    def updateState(self, bfdSession, state, rxInterval):
        bfdSession.setState(state)
        txInterval = bfdSession.getTxInterval()
        if txInterval != rxInterval:
            bfdSession.setTxInterval(rxInterval)

    # Used as a callback if a BFD packet is received
    def receivedPacket(self, pkt):
        if SCION in pkt:
            if pkt[SCION].nextHdr == 0xCB:
                # Set ingress interface
                mac = binascii.unhexlify(str(pkt[Ether].src).replace(':', ''))
                for i in range(len(self.egressPorts)):
                    if self.egressPorts[i] == int.from_bytes(mac, byteorder='big'):
                        ingress = self.egressInterfaces[i]
                # Perform checks to verify received BFD packet is valid
                if pkt[BFD].version != 1:
                    return
                if pkt[BFD].flags.A == 0 and pkt[BFD].len < 24:
                    return
                if pkt[BFD].flags.A == 1 and pkt[BFD].len < 26:
                    return
                if pkt[BFD].len > pkt[SCION].payloadLen:
                    return
                if pkt[BFD].detect_mult == 0:
                    return
                if pkt[BFD].flags.M != 0:
                    return
                if pkt[BFD].my_discriminator == 0:
                    return
                if pkt[BFD].your_discriminator == 0 and (pkt[BFD].sta == BFD_UP or pkt[BFD].sta == BFD_INIT):
                    return
                # TODO: Authentication is not supported by this code so far... Can be implemented
                if pkt[BFD].flags.A == 1:
                    return
                logger.debug("Received valid BFD Packet from %x-%x on %s:%s", pkt[SCION].srcISD, pkt[SCION].srcAS, socket.inet_ntoa(pkt[SCION].srcAddress), pkt[UDP].sport)
                # Match the packet to a BFD session
                for i in range(len(self.egressInterfaces)):
                    if self.egressInterfaces[i] == ingress and ((pkt[SCION].srcAS != self.hostAS or pkt[SCION].srcISD != self.hostISD) or
                        (pkt[SCION].srcAS == self.hostAS and pkt[SCION].srcISD == self.hostISD and 
                         pkt[UDP].sport == self.dstUDPPorts[i] and socket.inet_ntoa(pkt[SCION].srcAddress) == self.dstIPs[i])):

                        # Get matching BFD session
                        bfdSession = self.bfdSessions[i]
                        logger.debug("Found BFD Session: %s", bfdSession)

                        # Set received discriminator - function checks, whether it is valid and
                        # only performs set, if the value has changed
                        if (self.bfdSessions[i].setYourDiscrimi(pkt[BFD].my_discriminator) >= 0):
                            state = bfdSession.getState()
                            # Implementation of the BFD state machine
                            if pkt[BFD].sta == BFD_DOWN:
                                if state == BFD_DOWN:
                                    self.updateState(bfdSession, BFD_INIT, pkt[BFD].min_rx_interval)
                                if state == BFD_UP:
                                    self.updateState(bfdSession, BFD_DOWN, 1000000)
                            if pkt[BFD].sta == BFD_INIT:
                                if state != BFD_UP:
                                    self.updateState(bfdSession, BFD_UP, pkt[BFD].min_rx_interval)
                            if pkt[BFD].sta == BFD_UP:
                                if state == BFD_INIT:
                                    self.updateState(bfdSession, BFD_UP, pkt[BFD].min_rx_interval)

                        # Reset timeout for the session using the longer interval (either the own interval or the peer's interval)
                        minTxInterval = bfdSession.getTxInterval()
                        if minTxInterval < pkt[BFD].min_tx_interval:
                            minTxInterval = pkt[BFD].min_tx_interval
                                
                        bfdSession.setLastRxTime(pkt[BFD].detect_mult * minTxInterval / 1000000)
                        return

    # Run BFD session handler
    def run(self):
        # Start each session in an own process
        for session in self.bfdSessions:
            newProcess = Process(target=session.run)
            # Use deamon to stop process automatically when class is destroyed
            newProcess.daemon = True
            newProcess.start()
            # Safe all session processes
            self.bfdProcesses.append(newProcess)

bind_layers(Ether, Ether, type = 0x5C10)

