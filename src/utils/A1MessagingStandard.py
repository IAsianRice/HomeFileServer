import struct
from typing import Callable


class Transmission:
    NORMAL = 0b00000000
    STREAMED = 0b00000010


class EncryptionMethod:
    ASYMMETRIC = 1
    SYMMETRIC = 2
    NONE = 3


def format_request_message(data: bytes,
                           message_type: bytes = Transmission.NORMAL,
                           transmission_id: int = 0,
                           size: int = 0,
                           encryption_method: bytes = EncryptionMethod.NONE,
                           request_id: int = 0) -> bytes:
    message_header = struct.pack('<BQQBQ', message_type, transmission_id, size, encryption_method, request_id)
    return message_header + data
    pass


def format_intermittent_message(data: bytes,
                                transmission_id: int,
                                size: int,
                                terminated: bool,
                                message_num: int) -> bytes:
    message_header = struct.pack('<BQQBQ', 0b00000001, transmission_id, size, terminated, message_num)
    return message_header + data
    pass


def format_secure_request_message(encryption_function: Callable[[bytes], bytes],
                                  data: bytes,
                                  message_type: bytes = Transmission.NORMAL,
                                  transmission_id: int = 0,
                                  size: int = 0,
                                  encryption_method: bytes = EncryptionMethod.NONE,
                                  request_id: int = 0) -> bytes:
    message_header = encryption_function(struct.pack('<BQQBQ', message_type, transmission_id, size, encryption_method, request_id))
    return message_header + data
    pass


def format_secure_intermittent_message(encryption_function: Callable[[bytes], bytes],
                                       data: bytes,
                                       transmission_id: int,
                                       size: int,
                                       terminated: bool,
                                       encryption_method: bytes = EncryptionMethod.NONE) -> bytes:
    message_header = encryption_function(struct.pack('<BQQBQ', 0b00000001, transmission_id, size, encryption_method, terminated))
    return message_header + data
    pass
