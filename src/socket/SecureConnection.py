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
    """
    Manages a secure connection with a client accepted by the server.

    The `SecureConnection` class handles the handshaking process, including the exchange of public keys and symmetric keys
    between the server and the client. It provides callbacks for handling the collected data and manages the parsing of
    data packets by interpreting both the header and the corresponding data.

    Attributes:
        client_socket (socket.socket): The socket representing the connection with the client.
        server_private_key (Crypto.PublicKey.RSA._RSAobj): The server's private key for encryption and decryption.
        client_public_key (Crypto.PublicKey.RSA._RSAobj): The client's public key for encryption and decryption.
        symmetric_key (bytes): The shared symmetric key for symmetric encryption.

    Methods:
        __init__(self, client_socket, server_private_key, client_public_key, symmetric_key):
            Initializes a new instance of the SecureConnection class.

        receive_data(self):
            Receives and processes data from the connected client.

        send_data(self, data):
            Sends encrypted and formatted data to the connected client.

        handle_received_data(self, header, data):
            Callback method to handle the received data after parsing.

        parse_data_packet(self, packet):
            Parses a data packet, extracting the header and data portions.

    Example:
        # Create a SecureConnection instance
        secure_connection = SecureConnection(client_socket, server_private_key, client_public_key, symmetric_key)

        # Start receiving and processing data
        secure_connection.receive_data()

        # Send data to the connected client
        secure_connection.send_data(b"Hello, client!")

    Note:
        This class assumes that encryption and decryption methods (not provided in this docstring) are available
        for secure communication.
    """

    def __init__(self, client_socket: socket,
                 secure_communication: SecureCommunication,
                 address: str,
                 log_buffer_callback: Callable,
                 on_stop_callback: Callable,
                 request_handler: Union[Callable[[int, DataReceiver], None], None] = None):
        self.socket: socket = client_socket
        self.socket_buffer: SocketBuffer = SocketBuffer(client_socket)
        self.secure_communication: SecureCommunication = secure_communication
        self.client_pub_key: RSAPublicKey | None = None
        self.log_buffer: Queue = Queue(64)
        self.running: bool = True
        self.address: str = address
        self.log_buffer_callback: Callable = log_buffer_callback
        self.on_stop_callback: Callable = on_stop_callback
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
        self.on_stop_callback()
        pass

    def start(self):
        try:
            # Handshake Connection with Client
            self.handshake_connection()  # server initiates handshake

            # Passively read from the client
            self.reading_thread = threading.Thread(target=self.reading)
            self.reading_thread.start()

        except Exception as e:
            self.running = False
            self.log(f"Unexpected (start) error: {e}")

    def handshake_connection(self):
        try:
            self.log(f"(Send public key): {1}")
            # Send public key
            self.socket.send(self.secure_communication.get_public_rsa_key_pem() + b'\x04')

            self.log(f"(Get Client Pub Key): {1}")
            # Get Client Pub Key
            header_data = self.read_header()
            self.client_pub_key = serialization.load_pem_public_key(self.parse_public_key(header_data),
                                                                    backend=default_backend())

            self.log(f"(Send Symmetric Key): {1}")
            # Send Symmetric Key
            self.send_asymmetric_encrypted_formatted_message(
                base64.b64encode(self.secure_communication.get_symmetric_key_bytes())
                + b'\x03'
                + self.secure_communication.symmetric_key_iv, 0)

            self.log(f"Handshake Completed")

        except Exception as e:
            self.log(f"Unexpected (handshake_connection) error: {e}")

    # Called for each Connection
    def reading(self):  # Threaded
        # Read and handle incoming messages
        try:
            while self.running:
                self._reading()

        except Exception as e:
            self.log(f"Unexpected (reading) error: {e}")

        self.log("I have Stopped!")
        self.stop()

    def _reading(self):
        if self.running and not self.socket_buffer.inUse:
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
            self.log(f"(read_header): {1}")
            chunk_size = self.secure_communication.get_asymmetric_chunk_size()
            self.log(f"(read_header): {2}")
            buffer = self.socket_buffer.recv(chunk_size)
            self.log(f"(read_header): {3}")
            self.log(f"(read_header) buffer: {''.join([hex(byte)[2:].zfill(2) for byte in buffer])}")
            self.log(f"(read_header) buffer length: {len(buffer)}")
            header = self.secure_communication.asymmetric_decrypt_message(buffer)
            self.log(f"(read_header) header: {''.join([hex(byte)[2:].zfill(2) for byte in header])}")
            self.log(f"(read_header): {4}")
            return bytes(header)
        except Exception as e:
            self.log(f"Unexpected (read_header) error: {e}")
            self.running = False

    def parse_public_key(self, header: bytes) -> bytes:
        try:
            message_flags, _, body_size = struct.unpack('<BQQ', header[:17])
            self.log(f"(parse_header): {body_size}")
            public_key_PEM: bytes = bytes()
            for i in range(0, body_size):
                data = self.socket_buffer.recv(self.secure_communication.get_asymmetric_chunk_size())
                public_key_PEM += self.secure_communication.asymmetric_decrypt_message(data)

            return public_key_PEM

        except Exception as e:
            self.log(f"Unexpected (parse_header) error: {e}")
            self.running = False

    def _get_asymmetric_data(self, body_size: int) -> bytes:
        data = bytes()
        for _ in range(0, body_size):
            data_in = self.socket_buffer.recv(self.secure_communication.get_asymmetric_chunk_size())
            data += self.secure_communication.asymmetric_decrypt_message(data_in)
        return data

    def _get_symmetric_data(self, body_size: int) -> bytes:
        data_in = self.socket_buffer.recv(body_size)
        data = self.secure_communication.symmetric_decrypt_data(data_in)
        return data

    def parse_header(self, header: bytes):
        """
        Parses the header and decrypts the body from the client socket.

        Args:
        """
        try:
            message_flags, transmission_id, body_size, encryption_method = struct.unpack('<BQQB', header[:18])

            self.log(f"(parse_header) transmission_id: {transmission_id}")
            self.log(f"(parse_header) body_size: {body_size}")
            self.log(f"(parse_header) message_flags: {bin(message_flags)[2:].zfill(8)}")
            self.log(f"(parse_header) encryption_method: {encryption_method}")

            if message_flags & 0b00000001:  # Intermittent Message
                self.log(f"(parse_header) Intermittent Message")
                terminated = struct.unpack('<Q', header[18:26])[0]
                self.log(f"(parse_header) terminated: {terminated}")
                data_receiver = self.transmission_streams[transmission_id]
                if terminated:
                    self.log(f"(parse_header) TERMINATING")
                    data_receiver.terminate()
            else:  # Request Message
                self.log(f"(parse_header) Request Message")
                data_receiver = DataReceiver()
                request = struct.unpack('<Q', header[18:26])[0]
                self.request_handler(request, data_receiver)

            if encryption_method == 0x01:  # Asymmetric Encryption
                self.log(f"(parse_header) Asymmetric Encryption")
                data_in = self._get_asymmetric_data(body_size)
                self.log(f"(parse_header): {''.join([hex(byte)[2:].zfill(2) for byte in data_in])}")
                data_receiver.push_data(data_in)
            elif encryption_method == 0x02:  # Symmetric Encryption
                self.log(f"(parse_header) Symmetric Encryption")
                data_in = self._get_symmetric_data(body_size)
                self.log(f"(parse_header): {''.join([hex(byte)[2:].zfill(2) for byte in data_in])}")
                data_receiver.push_data(data_in)

            self.transmission_streams[transmission_id] = data_receiver

            if not message_flags & 0b00000010 and not message_flags & 0b00000001:  # Not Streamed
                self.log(f"(parse_header) Not Streamed")
                data_receiver.terminate()





        except Exception as e:
            self.log(f"Unexpected (parse_header) error: {e}")
            self.running = False

    def send_asymmetric_encrypted_formatted_message(self, data: Union[bytes, BufferedReader], request_id: int,
                                                    max_streamed_segments: int = 1):
        """
        Encrypts and formats a message using asymmetric encryption with RSA.

        Args:
            data (bytes): The input data to be encrypted.

        Returns:
            bytes: The encrypted and formatted message.
        """
        try:
            # Determine the chunk size based on the key size
            chunk_size = (self.client_pub_key.key_size // 8) - 11
            body_chunks = 0
            message_body = bytearray()

            def encryption_function(data_a: bytes) -> bytes:
                return encrypt_with_public_key(self.client_pub_key, data_a)

            if isinstance(data, bytes):
                self.log("is Bytes")
                # Encrypt data in chunks and build the message body
                for i in range(0, len(data), chunk_size):
                    end_index = min(i + chunk_size, len(data))
                    chunk = data[i:end_index]
                    encrypted_chunk = encryption_function(chunk)
                    message_body.extend(encrypted_chunk)
                    body_chunks += 1
                self.log("Send Data!")
                self.socket.send(
                    bytes(format_secure_request_message(encryption_function, message_body, size=body_chunks,
                                                        encryption_method=EncryptionMethod.ASYMMETRIC,
                                                        request_id=request_id)))
            elif isinstance(data, BufferedReader):
                self.log("is Buffered Reader")
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
                                    format_secure_intermittent_message(encryption_function, message_body,
                                                                       transmission_id,
                                                                       body_chunks, True, EncryptionMethod.ASYMMETRIC)))
                                break  # Exit the loop if there is no more data
                            encrypted_chunk = encryption_function(chunk)
                            message_body.extend(encrypted_chunk)
                            body_chunks += 1
                        if request_sent:
                            self.socket.send(bytes(
                                format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                                   body_chunks, False, EncryptionMethod.ASYMMETRIC)))
                            message_num += 1
                        else:
                            self.socket.send(bytes(format_secure_request_message(encryption_function, message_body,
                                                                                 size=body_chunks,
                                                                                 encryption_method=EncryptionMethod.ASYMMETRIC,
                                                                                 request_id=request_id)))
                # noinspection PyUnreachableCode
                self.release_unique_number(transmission_id)
        except Exception as e:
            self.log(f"Unexpected (parse_header) error: {e}")
            self.running = False
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
                                                               max_data_sent, True, EncryptionMethod.SYMMETRIC)))
                        break  # Exit the loop if there is no more data
                    encrypted_chunk = encryption_function(chunk)
                    message_body.extend(encrypted_chunk)
                    if request_sent:
                        self.socket.send(bytes(
                            format_secure_intermittent_message(encryption_function, message_body, transmission_id,
                                                               max_data_sent, False, EncryptionMethod.SYMMETRIC)))
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
