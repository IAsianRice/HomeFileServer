import base64
import struct
import threading
from io import BufferedReader
from queue import Queue
from socket import socket
from typing import Callable, Union

import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.socket.SecureCommunication import SecureCommunication
from src.utils.A1MessagingStandard import format_secure_request_message, EncryptionMethod, \
    format_secure_intermittent_message
from src.utils.DataReceiver import DataReceiver
from src.utils.SecureStreamBuffer import SecureStreamBuffer
from src.utils.SocketBuffer import SocketBuffer
from src.utils.utility import encrypt_with_public_key


class SecureConnection:
    def __init__(self, client_socket: socket,
                 secure_communication: SecureCommunication,
                 address: str,
                 log_buffer_callback: Callable,
                 on_stop_callback: Callable,
                 on_data_recv_callback: Callable[[SecureStreamBuffer], None],
                 request_handler: Callable[[int, DataReceiver], None]):
        self.socket: socket = client_socket
        self.socket_buffer: SocketBuffer = SocketBuffer(client_socket)
        self.secure_communication: SecureCommunication = secure_communication
        self.client_pub_key: RSAPublicKey | None = None
        self.log_buffer: Queue = Queue(64)
        self.running: bool = True
        self.address: str = address
        self.log_buffer_callback: Callable = log_buffer_callback
        self.on_stop_callback: Callable = on_stop_callback
        self.on_data_recv_callback: Callable[[SecureStreamBuffer], None] = on_data_recv_callback
        self.reading_thread: threading.Thread | None = None
        self.transmission_streams: dict[int, DataReceiver] = dict()
        self.request_handler: Callable[[int, DataReceiver], None] = request_handler
        self.available_numbers = set(range(256))

    def log(self, message):
        self.log_buffer.put(message)
        self.log_buffer_callback()
        pass

    def stop(self):  # TODO: Make Better
        self.socket.close()
        self.running = False
        if not (self.reading_thread is None):
            self.reading_thread.join()
        self.on_stop_callback()
        pass

    def start(self):
        try:
            # Handshake the Client
            self.handshake_connection()  # server initiates handshake

            # Passively Read the Client
            self.reading_thread = threading.Thread(target=self.reading)
            self.reading_thread.start()

        except Exception as e:
            self.stop()
            self.log(f"Unexpected (start) error: {e}")

    def handshake_connection(self):
        try:
            # Send public key
            self.socket.send(self.secure_communication.get_public_rsa_key_pem() + b'\x04')

            # Get Client Pub Key (data in: [Header][Segmented_Encrypted_PublicKey])
            header_data = self.read_header()
            self.parse_header(header_data)
            #self.get_client_key_handler(data_r)

            # Send Symmetric Key (data out: [Header][Segmented_Encrypted_PublicKey])
            self.send_asymmetric_encrypted_formatted_message(
                base64.b64encode(self.secure_communication.get_symmetric_key_bytes())
                + b'\x03'
                + self.secure_communication.symmetric_key_iv)

        except Exception as e:
            self.stop()
            self.log(f"Unexpected (handshake_connection) error (Failed Handshake): {e}")

    def get_client_key_handler(self, data_receiver: DataReceiver):
        try:
            def get_key(data: bytes):
                self.client_pub_key = serialization.load_pem_public_key(bytes(data), backend=default_backend())

            data_receiver.start_receiver_function(get_key)

        except Exception as e:
            self.log(f"Unexpected (get_client_key_handler) error: {e}")

    # Called for each Connection
    def reading(self):
        # Read and handle incoming messages
        try:
            while self.running:
                '''readable, _, _ = select.select([self.socket], [], [], 1)
                for readable_socket in readable:
                    if readable_socket == self.socket and'''
                self._reading()

        except Exception as e:
            self.log(f"Unexpected (reading) error: {e}")
        self.stop()

    def _reading(self):
        if self.running and not self.socket_buffer.inUse:
            print(self.socket_buffer.inUse)
            header_data = self.read_header()
            self.parse_header(header_data)

    def read_header(self):
        """
        Header (Strict) (245 Bytes):
        - Message Flags (1 byte)
            - Bit 0: Header Type [1:Intermittent, 0:Request]
            - Bit 1: Streamed [1: Yes (Intermittent Messaging), 0: No (Singular Message)]
        - Transmission ID (8 bytes)
        - Body Size (8 bytes)
        - Encryption Method (1 byte)
            - 0: No Encryption
            - 1: Asymmetric Encryption
            - 2: Symmetric Encryption
            - 3: ...
        - Request (8 bytes)


        Intermittent Header (Strict) (245 Bytes):
        - Message Flags (1 byte)
            - Bit 1: Header Type [1:Intermittent, 0:Request]
        - Transmission ID (8 Bytes)
        - Body Size (8 bytes)
        - Termination (1 byte)
        - Message Num (8 bytes)

        Returns:
            bytes: The decrypted header data.
        """
        try:
            chunk_size = self.secure_communication.get_asymmetric_chunk_size()
            buffer = self.socket_buffer.recv(chunk_size)
            header = self.secure_communication.asymmetric_decrypt_message(buffer)
            return bytes(header)
        except Exception as e:
            self.log(f"Unexpected (read_header) error: {e}")
            self.stop()

    def parse_header(self, header: bytes):
        """
        Parses the header and decrypts the body from the client socket.

        Args:
        """
        try:
            message_flags, transmission_id, body_size = struct.unpack('<BQQ', header[:17])

            if message_flags & 0b00000001:  # Intermittent Message
                terminated, message_number = struct.unpack('<BQ', header[17:26])
                data_receiver = self.transmission_streams[transmission_id]
                data_receiver.push_data(self.socket_buffer.recv(body_size))
                data_receiver.set_message_number(message_number)
                if terminated:
                    data_receiver.terminate()
            else:  # Request Message
                data_receiver = DataReceiver()
                encryption_method, request = struct.unpack('<BQ', header[17:26])
                if encryption_method == 0x01:  # Asymmetric Encryption
                    data_receiver.set_decrypter(self.secure_communication.asymmetric_decrypt_message)
                elif encryption_method == 0x02:  # Symmetric Encryption
                    data_receiver.set_decrypter(self.secure_communication.symmetric_decrypt_data)

                if message_flags & 0b00000010:  # Streamed
                    self.transmission_streams[transmission_id] = data_receiver
                else:  # Loaded
                    self.transmission_streams[transmission_id] = data_receiver.set_load_into_memory(True)

                data_receiver.push_data(self.socket_buffer.recv(body_size))

                self.request_handler(request, data_receiver)

        except Exception as e:
            self.log(f"Unexpected (parse_header) error: {e}")
            self.stop()

    def send_asymmetric_encrypted_formatted_message(self, data: Union[bytes, BufferedReader], request_id: int,
                                                    max_streamed_segments: int = 1):
        """
        Encrypts and formats a message using asymmetric encryption with RSA.

        Args:
            data (bytes): The input data to be encrypted.

        Returns:
            bytes: The encrypted and formatted message.
        """

        # Determine the chunk size based on the key size
        chunk_size = (self.client_pub_key.key_size // 8) - 11
        body_chunks = 0
        message_body = bytearray()

        def encryption_function(data_a: bytes) -> bytes:
            return encrypt_with_public_key(self.client_pub_key, data_a)

        if data is bytes:
            # Encrypt data in chunks and build the message body
            for i in range(0, len(data), chunk_size):
                end_index = min(i + chunk_size, len(data))
                chunk = data[i:end_index]
                encrypted_chunk = encryption_function(chunk)
                message_body.extend(encrypted_chunk)
                body_chunks += 1
            self.socket.send(bytes(format_secure_request_message(encryption_function, message_body, size=body_chunks,
                                                                 encryption_method=EncryptionMethod.ASYMMETRIC,
                                                                 request_id=request_id)))
        elif data is BufferedReader:
            request_sent = False
            message_num = 0
            transmission_id = self.get_unique_number()
            with data as file:
                while True:
                    body_chunks = 0
                    for i in range(0, max_streamed_segments):
                        chunk = file.read(chunk_size)
                        if not chunk:
                            self.socket.send(bytes(
                                format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                                   body_chunks, True, message_num)))
                            break  # Exit the loop if there is no more data
                        encrypted_chunk = encryption_function(chunk)
                        message_body.extend(encrypted_chunk)
                        body_chunks += 1
                    if request_sent:
                        self.socket.send(bytes(
                            format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                               body_chunks, False, message_num)))
                        message_num += 1
                    else:
                        self.socket.send(bytes(format_secure_request_message(encryption_function, message_body,
                                                                             size=body_chunks,
                                                                             encryption_method=EncryptionMethod.ASYMMETRIC,
                                                                             request_id=request_id)))
            # noinspection PyUnreachableCode
            self.release_unique_number(transmission_id)

        # Encrypt the message header and assemble the complete message

    def send_symmetric_encrypted_formatted_message(self, data: Union[bytes, BufferedReader], request_id: int,
                                                   max_data_sent: int = 4096):
        """
        Encrypts and formats a message using symmetric encryption with RSA key exchange.

        Args:
            data (bytes): The input data to be encrypted.
            bytes: The encrypted and formatted message.

        Returns:
            :param request_id:
        """

        message_body = bytearray()

        def encryption_function(data_a: bytes) -> bytes:
            return encrypt_with_public_key(self.client_pub_key, data_a)

        if data is bytes:
            # Encrypt data in chunks and build the message body
            chunk = data
            encrypted_body = encryption_function(chunk)
            self.socket.send(bytes(format_secure_request_message(encryption_function, encrypted_body, size=len(data),
                                                                 encryption_method=EncryptionMethod.SYMMETRIC,
                                                                 request_id=request_id)))
        elif data is BufferedReader:
            request_sent = False
            message_num = 0
            transmission_id = self.get_unique_number()
            with data as file:
                while True:
                    chunk = file.read(max_data_sent)
                    if not chunk:
                        self.socket.send(bytes(
                            format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                               max_data_sent, True, message_num)))
                        break  # Exit the loop if there is no more data
                    encrypted_chunk = encryption_function(chunk)
                    message_body.extend(encrypted_chunk)
                    if request_sent:
                        self.socket.send(bytes(
                            format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                               max_data_sent, False, message_num)))
                        message_num += 1
                    else:
                        self.socket.send(bytes(format_secure_request_message(encryption_function, message_body,
                                                                             size=max_data_sent,
                                                                             encryption_method=EncryptionMethod.SYMMETRIC,
                                                                             request_id=request_id)))
            # noinspection PyUnreachableCode
            self.release_unique_number(transmission_id)

    def get_unique_number(self):
        if not self.available_numbers:
            raise ValueError("No available unique numbers in the pool")
        unique_number = self.available_numbers.pop()
        return unique_number

    def release_unique_number(self, number):
        if number < 0 or number > 255:
            raise ValueError("Number must be in the range of 0-255")
        self.available_numbers.add(number)
