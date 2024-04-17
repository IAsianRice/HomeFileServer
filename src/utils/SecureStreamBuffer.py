import base64
import socket
import threading
from typing import Callable, Union

from cryptography.hazmat.primitives.ciphers import Cipher

from src.utils.SocketBuffer import SocketBuffer


class SecureStreamBuffer:
    def __init__(self, socket_buffer: SocketBuffer,
                 cipher_function: Callable[[bytes], bytes],
                 chunk_size: int,
                 delimiter: Union[bytes, None] = None,
                 segments: Union[int, None] = None):
        self.socket_buffer: SocketBuffer = socket_buffer
        self.delimiter: bytes = delimiter
        self.cipher_function: Callable[[bytes], bytes] = cipher_function
        self.chunk_size: int = chunk_size
        self.intermediate_buffer: bytearray = bytearray()
        self.segments: int = segments
        self.segments_read: int = 0
        self.socket_buffer.inUse = True
        #print(f"Started")
    def for_each_chunk_until_end(self, operation: Callable[[bytes], None]):
        try:
            chunk: bytes = self.recv_all_from_intermediate_buffer()
            #print(len(chunk))
            nondecoded: bytes = bytearray()
            if self.delimiter is not None:
                delimiterfound = False
                while not delimiterfound:
                    nondecoded = self.socket_buffer.recv(self.chunk_size, self.delimiter)
                    #print(len(nondecoded))
                    #print(nondecoded)
                    if self.delimiter in nondecoded:
                        nondecoded = nondecoded[:nondecoded.index(self.delimiter)]
                        delimiterfound = True
                    chunk += self.cipher_function(base64.b64decode(nondecoded))
                    operation(chunk)
                    chunk = bytearray()
            elif self.segments is not None:
                while self.segments_read < self.segments:
                    chunk += self.cipher_function(self.socket_buffer.recv(self.chunk_size))
                    operation(chunk)
                    chunk = bytearray()
                    self.segments_read += 1
            else:
                raise Exception("SecureStreamBuffer: delimiter and segments are not defined")
            self.socket_buffer.inUse = False
        except Exception as e:
            print(f"Unexpected (for_each_chunk_until_end) error: {e}")

    def read_until_end(self) -> bytes:
        try:
            data: bytearray = bytearray()
            if self.delimiter is not None:
                data: bytearray = self.recv_all_from_intermediate_buffer()
                while self.delimiter not in data:
                    data += self.cipher_function(base64.b64decode(self.socket_buffer.recv(self.chunk_size, self.delimiter)))
                data = data[:self.delimiter]
            elif self.segments is not None:
                data: bytearray = self.recv_all_from_intermediate_buffer()
                while self.segments_read < self.segments:
                    data += self.cipher_function(self.socket_buffer.recv(self.chunk_size))
                    self.segments_read += 1
                data = data[:self.delimiter]
            else:
                raise Exception("SecureStreamBuffer: delimiter and segments are not defined")
            self.socket_buffer.inUse = False
            return data
        except Exception as e:
            print(f"Unexpected (read_until_end) error: {e}")

    def read_until_delimiter(self, stopping_delimiter: bytes) -> bytes:
        try:
            data: bytearray = bytearray()
            if self.delimiter is not None:
                data: bytearray = self.recv_all_from_intermediate_buffer()
                while stopping_delimiter not in data:
                    tempdata = base64.b64decode(self.socket_buffer.recv(self.chunk_size))
                    data += self.cipher_function(tempdata)
                    self.segments_read += 1
                self.intermediate_buffer += data[data.index(stopping_delimiter) + 1:]
                data = data[:data.index(stopping_delimiter)]
            elif self.segments is not None:
                data: bytearray = self.recv_all_from_intermediate_buffer()
                while stopping_delimiter not in data:
                    tempdata = self.socket_buffer.recv(self.chunk_size)
                    data += self.cipher_function(tempdata)
                    self.segments_read += 1
                self.intermediate_buffer += data[data.index(stopping_delimiter) + 1:]
                data = data[:data.index(stopping_delimiter)]
            return data
        except Exception as e:
            print(f"Unexpected (read_until_delimiter) error: {e}")

    def recv_all_from_intermediate_buffer(self) -> bytearray:
        data = self.intermediate_buffer
        self.intermediate_buffer = bytearray()
        return data
