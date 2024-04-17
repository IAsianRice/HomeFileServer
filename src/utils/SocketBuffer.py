import socket
from typing import Union


class SocketBuffer:
    def __init__(self, socket: socket):
        self.socket: socket = socket
        self.intermediate_buffer: bytes = bytearray()
        self.inUse: bool = False

    def recv(self, num_bytes: int, delimiter: Union[bytes, None] = None) -> bytes:
        try:
            new_data_num = num_bytes - len(self.intermediate_buffer)
            #print(f"recv 1: {new_data_num}")
            #print(f"recv 2: {' '.join(hex(b) for b in self.intermediate_buffer)}")
            data: bytes = bytearray()
            if new_data_num > 0:
                data = self.recv_all_from_intermediate_buffer() + self.socket.recv(new_data_num)
            else:
                data = self.recv_from_intermediate_buffer(num_bytes)

            #print(f"recv 3: {' '.join(hex(b) for b in data)}")
            if delimiter is None:
                return data
            else:
                if delimiter in data:
                    self.intermediate_buffer += data[data.index(delimiter) + 1:]
                    return data[:data.index(delimiter) + 1]
                else:
                    return data
        except Exception as e:
            print(f"Unexpected (recv) error: {e}")

    def recv_from_intermediate_buffer(self, num_bytes: int) -> bytes:
        data = self.intermediate_buffer[:num_bytes]
        self.intermediate_buffer = self.intermediate_buffer[num_bytes + 1:]
        return data

    def recv_all_from_intermediate_buffer(self) -> bytes:
        data = self.intermediate_buffer
        self.intermediate_buffer = bytearray()
        return data

