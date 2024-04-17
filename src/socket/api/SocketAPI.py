import json
from dataclasses import dataclass
from typing import Callable

from src.socket.SecureConnection import SecureConnection
from src.utils.DataReceiver import DataReceiver
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

    def req_handler(self, secure_connection: SecureConnection, request_number: int, data_receiver: DataReceiver):
        try:
            secure_connection.log(f"Request Num {request_number}")
            if secure_connection not in self.association.keys():
                self.association[secure_connection] = tag(isAuthenticated=False, username="")
            if request_number == 1:  # login
                self.req_login(secure_connection, data_receiver)  # pass data through, passed the delimiter
            elif request_number == 2:  # mkusr
                self.req_make_user(secure_connection, data_receiver)  # pass data through, passed the delimiter
            elif request_number == 3:  # getdir
                self.req_get_user_directory(secure_connection, data_receiver)  # pass data through, passed the delimiter
            elif request_number == 4:  # getmasterdir
                self.req_get_master_directory(secure_connection,
                                              data_receiver)  # pass data through, passed the delimiter
            elif request_number == 5:  # sfile
                self.req_save_file(secure_connection, data_receiver)  # pass data through, passed the delimiter
            else:
                self.req_message(secure_connection, data_receiver)  # pass data through, passed the delimiter
            '''if not buffer.full():
                buffer.put(data.decode('utf-8') + "\n")
                buffer.put(request)
                buffer.put(data[request_index + 1:].decode('utf-8'))'''
        except Exception as e:
            self.application.server.buffer.put(f"Unexpected (req_handler) error: {e}")

    def req_login(self, conn: SecureConnection, data_receiver: DataReceiver):
        conn.log("Request")

        def _(dr: DataReceiver):
            try:
                conn.log("Executing")
                if not self.association[conn].isAuthenticated:
                    data = dr.get_data_until_terminated()
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
                        conn.log("Authenticated")
                        conn.send_asymmetric_encrypted_formatted_message(b'authorized\x03', 2)
                    else:
                        conn.log("Unauthenticated")
                        conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03', 3)
                    conn.log("Finished")
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'Already Authorized\x03', 4)
            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(_)

    def req_message(self, conn: SecureConnection, data_receiver: DataReceiver):
        def _(dr: DataReceiver):
            try:
                if self.association[conn].isAuthenticated:
                    self.application.server.buffer.put(dr.get_data_until_terminated().decode('utf-8'))
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03', 3)

            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(_)

    def req_make_user(self, conn: SecureConnection, data_receiver: DataReceiver):
        def function(data: bytes):
            try:
                if self.association[conn].isAuthenticated:
                    username = data[:data.index(0x03)].decode('utf-8')
                    data = data[data.index(0x03) + 1:]
                    password = data[:data.index(0x03)].decode('utf-8')
                    role = data[data.index(0x03) + 1:].decode('utf-8')
                    self.application.users.add_user(username, password, role)
            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(function)

    def req_get_user_directory(self, conn: SecureConnection, data_receiver: DataReceiver):
        def function(data: bytes):
            try:
                if self.association[conn].isAuthenticated:
                    dirTree = get_directory_structure(f"usersDir/{self.association[conn].username}")
                    conn.send_symmetric_encrypted_formatted_message(
                        b'dirdata\x03' + json.dumps(dirTree).encode('utf-8'), 1)
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03', 3)
            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(function)

    def req_get_master_directory(self, conn: SecureConnection, data_receiver: DataReceiver):
        def function(data: bytes):
            try:
                if self.association[conn].isAuthenticated and self.application.users.is_admin(
                        self.association[conn].username):
                    dir = get_directory_structure(f"usersDir")
                    conn.send_symmetric_encrypted_formatted_message(json.dumps(dir).encode('utf-8'), 1)
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03', 3)
            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(function)

    def req_send_file(self, conn: SecureConnection, data_receiver: DataReceiver):
        def function(data: bytes):
            try:
                if self.association[conn].isAuthenticated:
                    dir = get_directory_structure(f"usersDir")
                    conn.send_symmetric_encrypted_formatted_message(b'dirdata\x03' + json.dumps(dir).encode('utf-8'), 1)
                else:
                    conn.send_asymmetric_encrypted_formatted_message(b'unauthorized\x03', 3)
            except Exception as e:
                self.application.server.buffer.put(f"Unexpected error: {e}")

        data_receiver.start_receiver_function(function)

    def req_save_file(self, conn: SecureConnection, data_receiver: DataReceiver):
        conn.log("req_save_file")
        def _(dr: DataReceiver):
            if self.association[conn].isAuthenticated:
                name = dr.get_data_until_delimiter(b'\x03').decode('utf-8')
                conn.log("GOT NAME!")
                with open(f"usersDir/{self.association[conn].username}/{name}", 'wb') as file:
                    def _(data: bytes):
                        try:
                            file.write(data)
                        except Exception as e:
                            self.application.server.buffer.put(f"Unexpected error: {e}")

                    conn.log("START FILE STREAMING")
                    dr.stream_data_until_terminated_into(_)
                conn.log("Finished!")
            else:
                conn.log("Unauthorized!")

        data_receiver.start_receiver_function(_)
