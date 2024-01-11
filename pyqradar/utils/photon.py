import json
import signal
import sys
import threading

from pyqradar.utils.photon_packet_parser_mod import PhotonPacketParser

from pyqradar.utils.flask import socketio
from pyqradar.utils.logging import LoggerManager, logging

logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.all import UDP, sniff

photon = LoggerManager("photon")


def JSONizer(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    else:
        raise TypeError(f"Unserializable type: {type(obj)}")


class Photon:
    def __init__(self) -> None:
        self.parser = PhotonPacketParser(
            self.on_event, self.on_request, self.on_response
        )
        self.stop_sniffing = threading.Event()
        self.sniffing_thread = threading.Thread(target=self.start_sniffing)
        self.sniffing_thread.daemon = True
        self.sniffing_thread.start()

        signal.signal(signal.SIGINT, self.handle_exit)

    def start_sniffing(self):
        sniff(
            prn=self.packet_callback, filter="udp and (port 5056 or port 5055)", store=0
        )

    def packet_callback(self, packet):
        if UDP in packet:
            udp_payload = bytes(packet[UDP].payload)

            try:
                self.parser.handle_payload(udp_payload)
            except:
                pass

    def handle_exit(self, signum, frame):
        self.stop_sniffing.set()
        sys.exit(0)

    def stop(self):
        self.stop_sniffing.set()
        self.sniffing_thread.join()

    @staticmethod
    def on_event(data):
        if not 252 in data.parameters and not 253 in data.parameters:
            return

        socketio.send(
            json.dumps(
                {"code": "event", "dictionary": {"parameters": data.parameters}},
                default=JSONizer,
                separators=(",", ":"),
            )
        )

    @staticmethod
    def on_request(data):
        if not 252 in data.parameters and not 253 in data.parameters:
            return

        socketio.send(
            json.dumps(
                {"code": "request", "dictionary": {"parameters": data.parameters}},
                default=JSONizer,
                separators=(",", ":"),
            )
        )

    @staticmethod
    def on_response(data):
        pass
