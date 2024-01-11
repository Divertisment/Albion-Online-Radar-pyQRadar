import io
from pyqradar.utils.photon_packet_parser_mod.message_type import MessageType
from pyqradar.utils.photon_packet_parser_mod.command_type import CommandType
from pyqradar.utils.photon_packet_parser_mod.segmented_package import SegmentedPackage
from pyqradar.utils.photon_packet_parser_mod.protocol16_deserializer import Protocol16Deserializer
from pyqradar.utils.photon_packet_parser_mod.byte_reader import ByteReader
from pyqradar.utils.photon_packet_parser_mod.crc_calculator import CrcCalculator
from pyqradar.utils.photon_packet_parser_mod.number_serializer import NumberSerializer

COMMAND_HEADER_LENGTH = 12
PHOTON_HEADER_LENGTH = 12

class PhotonPacketParser:
    def __init__(self, on_event, on_request, on_response):
        self._pending_segments = {}
        self.on_event = on_event
        self.on_request = on_request
        self.on_response = on_response

    def handle_payload(self, payload):
        payload = io.BytesIO(payload)

        if payload.getbuffer().nbytes < PHOTON_HEADER_LENGTH:
            return

        peer_id = NumberSerializer.deserialize_short(payload)
        flags = ByteReader.read_byte(payload)[0]
        command_count = ByteReader.read_byte(payload)[0]
        timestamp = NumberSerializer.deserialize_int(payload)
        challenge = NumberSerializer.deserialize_int(payload)
        is_encrypted = flags == 1
        is_crc_enabled = flags == 0xCC

        if is_encrypted:
            return

        if is_crc_enabled:
            print("CRC is enabled")
            offset = payload.tell()
            payload.seek(0)
            crc, _ = NumberSerializer.deserialize_int(payload)

            payload.seek(offset)
            payload = NumberSerializer.serialize(0, payload)

            if crc != CrcCalculator.calculate(payload, payload.getbuffer().nbytes):
                return

        for _ in range(command_count):
            self.handle_command(payload, command_count)

    def handle_command(self, source: io.BytesIO, command_count: int):
        command_type = ByteReader.read_byte(source)

        if not command_type:
            return

        command_type = command_type[0]
        channel_id = ByteReader.read_byte(source)[0]
        command_flags = ByteReader.read_byte(source)[0]

        source.read(1)

        command_length = NumberSerializer.deserialize_int(source)
        sequence_number = NumberSerializer.deserialize_int(source)

        command_length -= COMMAND_HEADER_LENGTH

        if command_type == CommandType.Disconnect.value:
            return
        elif command_type == CommandType.SendUnreliable.value:
            source.read(4)
            command_length -= 4
            self.handle_send_reliable(source, command_length)
        elif command_type == CommandType.SendReliable.value:
            self.handle_send_reliable(source, command_length)
        elif command_type == CommandType.SendFragment.value:
            self.handle_send_fragment(source, command_length)
        else:
            source.read(command_length)

    def handle_send_reliable(self, source: io.BytesIO, command_length: int):
        source.read(1)
        command_length -= 1
        message_type = ByteReader.read_byte(source)[0]
        command_length -= 1
        operation_length = command_length

        payload = io.BytesIO(source.read(operation_length))

        if message_type == MessageType.OperationRequest.value:
            request_data = Protocol16Deserializer.deserialize_operation_request(payload)
            self.on_request(request_data)
        elif message_type == MessageType.OperationResponse.value:
            response_data = Protocol16Deserializer.deserialize_operation_response(payload)
            self.on_request(response_data)
        elif message_type == MessageType.Event.value:
            event_data = Protocol16Deserializer.deserialize_event_data(payload)
            self.on_event(event_data)

    def handle_send_fragment(self, source: io.BytesIO, command_length: int):
        sequence_number = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_count = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_number = NumberSerializer.deserialize_int(source)
        command_length -= 4
        total_length = NumberSerializer.deserialize_int(source)
        command_length -= 4
        fragment_offset = NumberSerializer.deserialize_int(source)
        command_length -= 4

        fragment_length = command_length

        self.handle_segmented_payload(sequence_number, total_length, fragment_length, fragment_offset, source)

    def get_segmented_package(self, start_sequence_number, total_length):
        if start_sequence_number in self._pending_segments:
            return self._pending_segments[start_sequence_number]

        segmented_package = SegmentedPackage(total_length=total_length, total_payload=bytearray(total_length))

        self._pending_segments[start_sequence_number] = segmented_package

        return segmented_package

    def handle_segmented_payload(self, start_sequence_number, total_length, fragment_length, fragment_offset, source):
        segmented_package = self.get_segmented_package(start_sequence_number, total_length)

        for i in range(fragment_length):
            segmented_package.total_payload[fragment_offset + i] = source.read(1)[0]

        segmented_package.bytes_written += fragment_length

        if segmented_package.bytes_written >= segmented_package.total_length:
            self._pending_segments.pop(start_sequence_number)
            self.handle_finished_segmented_package(segmented_package.total_payload)

    def handle_finished_segmented_package(self, total_payload: bytearray):
        command_length = len(total_payload)
        self.handle_send_reliable(io.BytesIO(total_payload), command_length)
