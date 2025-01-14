#!/usr/bin/env python3

# Copyright (c) 2019, Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ast import TypeAlias
from enum import IntEnum
import sys
import os

is_standalone = __name__ == "__main__"


if is_standalone:
    sys.path.insert(0, os.getcwd())

import re
import signal
import struct
import threading
import time
import logging
from argparse import ArgumentParser
from binascii import a2b_hex
from serial import Serial, serialutil
from serial.tools.list_ports import comports
from multiprocessing import Queue, Process
from dataclasses import dataclass
from threading import Thread


@dataclass
class SnifferPacket:
    content: bytes
    timestamp: int
    lqi: int
    rssi: int


class ControlPacket:
    content: bytes


class ExitEvent:
    pass


class DLT(IntEnum):
    # Various options for pcap files: http://www.tcpdump.org/linktypes.html
    DLT_USER0 = 147
    DLT_IEEE802_15_4_NOFCS = 230
    DLT_IEEE802_15_4_TAP = 283


class Nrf802154Sniffer:

    # USB device identification.
    NORDICSEMI_VID = 0x1915
    SNIFFER_802154_PID = 0x154B

    # Helpers for Wireshark argument parsing.
    CTRL_ARG_CHANNEL = 0
    CTRL_ARG_LOGGER = 6

    # Pattern for packets being printed over serial.
    RCV_REGEX = r"received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(-?\d+)"

    TIMER_MAX = 2**32

    def __init__(self, connection_open_timeout=None):
        self.serial = None
        self.queue = Queue()
        self.running = threading.Event()
        self.setup_done = threading.Event()
        self.setup_done.clear()
        self.logger = logging.getLogger(__name__)
        self.dev = None
        self.channel = None
        self.dlt = None
        self.processes: list[Process] = []
        self.threads: list[Thread] = []
        self.connection_open_timeout = connection_open_timeout

    @classmethod
    def serial_reader(
        cls,
        serial_port: str,
        queue: Queue,
    ) -> None:
        serial = Serial(serial_port, exclusive=True)
        while True:
            value = serial.readline()
            try:
                packet = cls.parse_packet(value)
                queue.put(packet)
            except:
                ...

    @classmethod
    def parse_packet(cls, value: bytes) -> SnifferPacket:
        m = re.search(cls.RCV_REGEX, str(value))
        if m:
            packet = a2b_hex(m.group(1)[:-4])
            rssi = int(m.group(2))
            lqi = int(m.group(3))
            timestamp = int(m.group(4))
            return SnifferPacket(
                content=packet, timestamp=timestamp, lqi=lqi, rssi=rssi
            )
        else:
            raise Exception()

    @classmethod
    def control_reader(
        cls,
        control_in: str,
        queue: Queue,
    ) -> None:
        with open(control_in, "rb", 0) as control_in_fifo:
            try:
                while True:
                    value = control_in_fifo.read()
                    sys.stderr.write(f"aaa{value}")
            except:
                sys.stderr.write(f"aaa")
                queue.put(ExitEvent())

    @staticmethod
    def parse_control(value: bytes) -> ControlPacket:
        return ControlPacket(content=value)

    # def stop_sig_handler(self, *args, **kwargs):
    #     """
    #     Function responsible for stopping the sniffer firmware and closing all threads.
    #     """
    #     # Let's wait with closing afer we're sure that the sniffer started. Protects us
    #     # from very short tests (NOTE: the serial_reader has a delayed start).
    #     while self.running.is_set() and not self.setup_done.is_set():
    #         time.sleep(1)

    #     if self.running.is_set():
    #         self.serial_queue.put(b"")
    #         self.serial_queue.put(b"sleep")
    #         self.running.clear()

    #         alive_threads = []

    #         for thread in self.threads:
    #             try:
    #                 thread.join(timeout=10)
    #                 if thread.is_alive() is True:
    #                     self.logger.error(
    #                         "Failed to stop thread {}".format(thread.name)
    #                     )
    #                     alive_threads.append(thread)
    #             except RuntimeError:
    #                 # TODO: This may be called from one of threads from thread list - architecture problem
    #                 pass

    #         self.threads = alive_threads
    #     else:
    #         self.logger.warning(
    #             "Asked to stop {} while it was already stopped".format(self)
    #         )

    #     if self.serial is not None:
    #         if self.serial.is_open is True:
    #             self.serial.close()
    #         self.serial = None

    def stop_sig_handler(self, *args, **kwargs):
        self.stop()
        exit(0)

    def stop(self):
        for process in self.processes:
            process.kill()

    @staticmethod
    def extcap_interfaces():
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        res = []
        res.append(
            "extcap {version=0.7.2}{help=https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4}{display=nRF Sniffer for 802.15.4}"
        )
        for port in comports():
            if (
                port.vid == Nrf802154Sniffer.NORDICSEMI_VID
                and port.pid == Nrf802154Sniffer.SNIFFER_802154_PID
            ):
                res.append(
                    "interface {value=%s}{display=nRF Sniffer for 802.15.4}"
                    % (port.device,)
                )

        res.append(
            "control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}"
            % Nrf802154Sniffer.CTRL_ARG_LOGGER
        )

        return "\n".join(res)

    @staticmethod
    def extcap_dlts():
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        res = []
        res.append(
            "dlt {number=%d}{name=IEEE802_15_4_NOFCS}{display=IEEE 802.15.4 without FCS}"
            % DLT.DLT_IEEE802_15_4_NOFCS
        )
        res.append(
            "dlt {number=%d}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}"
            % DLT.DLT_IEEE802_15_4_TAP
        )
        res.append(
            "dlt {number=%d}{name=USER0}{display=User 0 (DLT=147)}" % DLT.DLT_USER0
        )

        return "\n".join(res)

    @staticmethod
    def extcap_config(option):
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        args = []
        values = []
        res = []

        args.append(
            (
                0,
                "--channel",
                "Channel",
                "IEEE 802.15.4 channel",
                "selector",
                "{required=true}{default=11}",
            )
        )
        args.append(
            (
                1,
                "--metadata",
                "Out-Of-Band meta-data",
                "Packet header containing out-of-band meta-data for channel, RSSI and LQI",
                "selector",
                "{default=none}",
            )
        )

        if len(option) <= 0:
            for arg in args:
                res.append(
                    "arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg
                )

            values = values + [
                (0, "%d" % i, "%d" % i, "true" if i == 11 else "false")
                for i in range(11, 27)
            ]

            values.append((1, "none", "None", "true"))
            values.append((1, "ieee802154-tap", "IEEE 802.15.4 TAP", "false"))
            values.append((1, "user", "Custom Lua dissector", "false"))

        for value in values:
            res.append("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)
        res.append(
            "control {number=4}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}"
        )
        return "\n".join(res)

    def pcap_header(self):
        """
        Returns pcap header to be written into pcap file.
        """
        header = bytearray()
        header += struct.pack("<L", int("a1b2c3d4", 16))
        header += struct.pack("<H", 2)  # Pcap Major Version
        header += struct.pack("<H", 4)  # Pcap Minor Version
        header += struct.pack("<I", int(0))  # Timezone
        header += struct.pack("<I", int(0))  # Accurancy of timestamps
        header += struct.pack("<L", int("000000ff", 16))  # Max Length of capture frame
        header += struct.pack("<L", self.dlt)  # DLT
        return header

    @staticmethod
    def pcap_packet(
        frame: bytes, dlt, channel: int, rssi: int, lqi: int, timestamp: int
    ) -> bytes:
        """
        Creates pcap packet to be seved in pcap file.
        """
        pcap = bytearray()

        caplength = len(frame)

        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            caplength += 28
        elif dlt == DLT.DLT_USER0:
            caplength += 6

        pcap += struct.pack("<L", timestamp // 1000000)  # Timestamp seconds
        pcap += struct.pack("<L", timestamp % 1000000)  # Timestamp microseconds
        pcap += struct.pack("<L", caplength)  # Length captured
        pcap += struct.pack("<L", caplength)  # Length in frame

        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            # Append TLVs according to 802.15.4 TAP specification:
            # https://github.com/jkcko/ieee802.15.4-tap
            pcap += struct.pack("<HH", 0, 28)
            pcap += struct.pack("<HHf", 1, 4, rssi)
            pcap += struct.pack("<HHHH", 3, 3, channel, 0)
            pcap += struct.pack("<HHI", 10, 1, lqi)
        elif dlt == DLT.DLT_USER0:
            pcap += struct.pack("<H", channel)
            pcap += struct.pack("<h", rssi)
            pcap += struct.pack("<H", lqi)

        pcap += frame

        return bytes(pcap)

    def append_process(self, target, args):
        if is_standalone and os.name == "nt":
            # On Windows, Wireshark uses TerminateProcess, so we don't have to worry about cleaning up.
            # We can't use subprocesses, because those won't be terminated by the system.
            self.threads.append(Thread(target=target, args=args))
        else:
            # Otherwise, on other systems we should make an attempt at graceful cleanup.
            # Given all the quirks, using subprocesses is the best bet at making things clean.
            self.processes.append(Process(target=target, args=args))

    def start_processes(self):
        procs = self.threads if (is_standalone and os.name == "nt") else self.processes
        for process in procs:
            process.start()

    def extcap_capture(
        self, fifo, dev, channel, metadata=None, control_in=None, control_out=None
    ):
        """
        Main method responsible for starting all other threads. In case of standalone execution this method will block
        until SIGTERM/SIGINT and/or stop_sig_handler disables the loop via self.running event.
        """

        self.channel = channel
        self.dev = dev
        self.running.set()

        if metadata == "ieee802154-tap":
            # For Wireshark 3.0 and later
            self.dlt = DLT.DLT_IEEE802_15_4_TAP
        elif metadata == "user":
            # For Wireshark 2.4 and 2.6
            self.dlt = DLT.DLT_USER0
        else:
            self.dlt = DLT.DLT_IEEE802_15_4_NOFCS

        serial = Serial(dev, exclusive=True, timeout=0.1)
        serial.write(b"sleep\r\n")
        serial.write(b"shell echo off\r\n")
        serial.flush()
        # serial.reset_input_buffer()
        while serial.readall():
            pass
        serial.close()

        serial = Serial(dev, exclusive=True)
        serial.write(b"channel " + bytes(str(channel).encode()) + b"\r\n")
        serial.write(b"receive\r\n")
        serial.flush()
        serial.close()

        self.append_process(target=self.serial_reader, args=(dev, self.queue))

        if control_in:
            self.append_process(
                target=self.control_reader, args=(control_in, self.queue)
            )

        self.start_processes()

        with open(fifo, "wb", 0) as fifo:
            fifo.write(self.pcap_header())
            fifo.flush()

            while packet := self.queue.get():
                sys.stderr.write("ev")
                match packet:
                    case SnifferPacket(content, timestamp, lqi, rssi):
                        pcap = self.pcap_packet(
                            content, self.dlt, channel, rssi, lqi, timestamp
                        )
                        fifo.write(pcap)
                    case ExitEvent():
                        sys.stderr.write("exit event")
                        self.stop()

    @staticmethod
    def parse_args():
        """
        Helper methods to make the standalone script work in console and wireshark.
        """
        parser = ArgumentParser(
            description="Extcap program for the nRF Sniffer for 802.15.4"
        )

        parser.add_argument(
            "--extcap-interfaces",
            help="Provide a list of interfaces to capture from",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-interface", help="Provide the interface to capture from"
        )
        parser.add_argument(
            "--extcap-dlts",
            help="Provide a list of dlts for the given interface",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-config",
            help="Provide a list of configurations for the given interface",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-reload-option", help="Reload elements for the given option"
        )
        parser.add_argument(
            "--capture", help="Start the capture routine", action="store_true"
        )
        parser.add_argument(
            "--fifo",
            help="Use together with capture to provide the fifo to dump data to",
        )
        parser.add_argument(
            "--extcap-capture-filter",
            help="Used together with capture to provide a capture filter",
        )
        parser.add_argument(
            "--extcap-control-in", help="Used to get control messages from toolbar"
        )
        parser.add_argument(
            "--extcap-control-out", help="Used to send control messages to toolbar"
        )

        parser.add_argument("--channel", help="IEEE 802.15.4 capture channel [11-26]")
        parser.add_argument(
            "--metadata", help="Meta-Data type to use for captured packets"
        )

        result, unknown = parser.parse_known_args()

        if result.capture and not result.extcap_interface:
            parser.error("--extcap-interface is required if --capture is present")

        return result

    def __str__(self):
        return "{} ({}) channel {}".format(type(self).__name__, self.dev, self.channel)

    def __repr__(self):
        return self.__str__()


if is_standalone:
    args = Nrf802154Sniffer.parse_args()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
    )

    sniffer_comm = Nrf802154Sniffer()

    if args.extcap_interfaces:
        print(sniffer_comm.extcap_interfaces())

    if args.extcap_dlts:
        print(sniffer_comm.extcap_dlts())

    if args.extcap_config:
        if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
            option = args.extcap_reload_option
        else:
            option = ""
        print(sniffer_comm.extcap_config(option))

    if args.capture and args.fifo:
        channel = args.channel if args.channel else 11
        signal.signal(signal.SIGINT, sniffer_comm.stop_sig_handler)
        signal.signal(signal.SIGTERM, sniffer_comm.stop_sig_handler)
        try:
            sniffer_comm.extcap_capture(
                args.fifo,
                args.extcap_interface,
                channel,
                args.metadata,
                args.extcap_control_in,
                args.extcap_control_out,
            )
        except KeyboardInterrupt as e:
            ...
            print("dupa")
        #     sniffer_comm.stop_sig_handler()
