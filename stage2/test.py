"""Test Runner for FIRE STORM: SUPERHEATED"""

import argparse
import struct
import time
import unittest
from pathlib import Path
from threading import Thread

from buffers import packets
from client import create_receiver, create_sender
from o import ps

parser = argparse.ArgumentParser(
    prog="fire-storm-superheated",
    description="Replay FIRE STORM: SUPERHEATED test traffic",
)
parser.add_argument(
    "-p",
    "--pcap",
    help="Don't run tests interactively, instead dumps packet buffers to optional file name",
    required=False,
    const="output.pcap",
    default=None,
    nargs="?",
)
parser.add_argument(
    "-q",
    "--quiet",
    help="Remove ASCII art command line output",
    action="store_true",
)


class TestSolution(unittest.TestCase):
    data_received: dict[int, bytes] = {}

    def receive_msg(self, thread_id: int) -> None:
        receiver = create_receiver(port=thread_id)

        try:
            while True:
                conn, _ = receiver.accept()
                conn_open = True
                while conn_open:
                    data = conn.recv(1024)

                    if len(data) == 0:
                        conn.close()
                        conn_open = False
                        break

                    if thread_id not in self.data_received:
                        self.data_received[thread_id] = b""
                    self.data_received[thread_id] += data

        except Exception:
            # print("Receiver thread - caught exception:", str(e))
            pass

        finally:
            receiver.close()

    def send_and_recv(
        self, packets: list[bytes], listen_ports: list[int] = [5745, 5744, 5746]
    ):
        sender = create_sender()
        receiver_threads: list[Thread] = []

        for port_no in listen_ports:
            receiver_threads.append(Thread(target=self.receive_msg, args=(port_no,)))
            receiver_threads[-1].start()

        time.sleep(1)
        for packet in packets:
            sender.sendall(packet)

        sender.close()

        for thread in receiver_threads:
            thread.join(timeout=5)

    def test_traffic(self):
        self.send_and_recv(packets.all)

        for i, packet in enumerate(packets.all):
            recv = False

            if i in packets.route1:
                self.assertIn(packet, self.data_received[5744])
                recv = True
            elif i in packets.route2:
                self.assertIn(packet, self.data_received[5746])
                recv = True

            if i in packets.route3:
                self.assertIn(packet, self.data_received[5745])
                recv = True

            if i in packets.route0:
                self.assertFalse(recv)


def write_pcap_file(output: Path, packets: list[bytes]):
    with output.open("wb") as file:
        seconds = 1582675200
        file.write(struct.pack(">IHHIIIHH", 0xA1B2C3D4, 2, 4, 0, 0, 65536, 0, 1))
        for packet in packets:
            file.write(struct.pack(">IIII", seconds, 0, len(packet), len(packet)))
            file.write(packet)
            seconds += 1


if __name__ == "__main__":
    args = parser.parse_args()
    if not args.quiet:
        print("""
        ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓██████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░
       ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
       ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
        ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓████████▓▒░▒▓██████▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░   ░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░
              ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
              ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
       ░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓███████▓▒░
        """)
    packets.all = ps(packets.all)
    if args.pcap is not None:
        write_pcap_file(Path(args.pcap), packets.all)
        print("Written to", Path(args.pcap))
    else:
        print("Running test...")
        unittest.main(exit=False)
