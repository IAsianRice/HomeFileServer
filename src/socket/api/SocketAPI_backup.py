import json
from dataclasses import dataclass
from typing import Callable

from src.socket.SecureConnection import SecureConnection
from src.utils.SecureStreamBuffer import SecureStreamBuffer
from src.utils.utility import encrypt_data, get_directory_structure, create_file, encrypt_bytes_data


@dataclass
class tag:
    isAuthenticated: bool
    username: str


class SocketAPI:
    def __init__(self, application):
        self.application = application
        self.association: dict[SecureConnection, tag] = {}

    def req_handler(self, conn: SecureConnection, secure_stream_buffer: SecureStreamBuffer):
        try:
            if conn not in self.association.keys():
                self.association[conn] = tag(isAuthenticated=False, username="")
            undecodedreq = secure_stream_buffer.read_until_delimiter(stopping_delimiter=bytes([0x03]))
            self.application.server.buffer.put(f"{' '.join(hex(b) for b in undecodedreq)}")
            request = undecodedreq.decode('utf-8')
            self.application.server.buffer.put(f"{request}")
            if request == 'login':
                self.req_login(conn, secure_stream_buffer.read_until_end())  # pass data through, passed the delimiter
            elif request == 'mkusr':
                self.req_make_user(conn, secure_stream_buffer.read_until_end())  # pass data through, passed the delimiter
            elif request == 'getdir':
                self.req_get_user_directory(conn, secure_stream_buffer.read_until_end())  # pass data through, passed the delimiter
            elif request == 'getmasterdir':
                self.req_get_master_directory(conn, secure_stream_buffer.read_until_end())  # pass data through, passed the delimiter
            elif request == 'sfile':
                self.req_save_file(conn, secure_stream_buffer)  # pass data through, passed the delimiter
            else:
                self.req_message(conn, secure_stream_buffer.read_until_end())  # pass data through, passed the delimiter
            '''if not buffer.full():
                buffer.put(data.decode('utf-8') + "\n")
                buffer.put(request)
                buffer.put(data[request_index + 1:].decode('utf-8'))'''
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected (req_handler) error: {e}")

    def req_login(self, conn: SecureConnection, data: bytes):
        self.application.server.buffer.put(data.decode('utf-8'))
        try:
            if not self.association[conn].isAuthenticated:
                username = data[:data.index(0x03)].decode('utf-8')
                password = data[data.index(0x03) + 1:].decode('utf-8')
                # self.application.server.buffer.put(f"{password}")
                self.association[conn].isAuthenticated = self.application.users.login(username, password)
                self.association[conn].username = username
                # original_bytes = "Authorized\n".encode("utf-8")
                # padding_size = 256 - len(original_bytes)
                # padded_bytes = original_bytes + b'\x00' * padding_size
                # print(padded_bytes.decode("utf-8"))
                # conn.client_socket.send(padded_bytes)
                # conn.client_socket.send(encrypt_data(conn.public_key, "Authorized\n"))
                if self.association[conn].isAuthenticated:
                    conn.send_asymmetric_encrypted_formatted_message(b'authorized\x03')
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03')
            else:
                conn.send_asymmetric_encrypted_formatted_message(b'Already Authorized\x03')
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_message(self, conn: SecureConnection, data: bytes):
        try:
            if self.association[conn].isAuthenticated:
                self.application.server.buffer.put(data.decode('utf-8'))
            else:
                conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03')

        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_make_user(self, conn: SecureConnection, data: bytes):
        try:
            if self.association[conn].isAuthenticated:
                username = data[:data.index(0x03)].decode('utf-8')
                data = data[data.index(0x03) + 1:]
                password = data[:data.index(0x03)].decode('utf-8')
                role = data[data.index(0x03) + 1:].decode('utf-8')
                self.application.users.add_user(username, password, role)
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_get_user_directory(self, conn: SecureConnection, data: bytes):
        try:
            if self.association[conn].isAuthenticated:
                dirTree = get_directory_structure(f"usersDir/{self.association[conn].username}")
                conn.send_symmetric_encrypted_formatted_message(b'dirdata\x03' + json.dumps(dirTree).encode('utf-8'))
            else:
                conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03')
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_get_master_directory(self, conn: SecureConnection, data: bytes):
        try:
            if self.association[conn].isAuthenticated and self.application.users.is_admin(
                    self.association[conn].username):
                dir = get_directory_structure(f"usersDir")
                conn.send_symmetric_encrypted_formatted_message(json.dumps(dir).encode('utf-8'))
            else:
                conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03')
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_send_file(self, conn: SecureConnection, data: bytes):
        try:
            if self.association[conn].isAuthenticated:
                dir = get_directory_structure(f"usersDir")
                conn.send_symmetric_encrypted_formatted_message(b'dirdata\x03' + json.dumps(dir).encode('utf-8'))
            else:
                conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03')
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")

    def req_save_file(self, conn: SecureConnection, secure_stream_buffer: SecureStreamBuffer):
        try:
            if self.association[conn].isAuthenticated:
                name = secure_stream_buffer.read_until_delimiter(stopping_delimiter=bytes([0x03])).decode('utf-8')
                with open(f"usersDir/{self.association[conn].username}/{name}", 'wb') as file:
                    def write_file(data: bytes):
                        file.write(data)
                    secure_stream_buffer.for_each_chunk_until_end(write_file)

        except Exception as e:
            self.application.server.buffer.put(f"Unexpected error: {e}")
