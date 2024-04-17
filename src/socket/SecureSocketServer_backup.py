import base64
import errno
import socket
import threading
from queue import Queue
from typing import Callable
import struct

import rsa
import select

from src.socket.SecureCommunication import SecureCommunication, SecureConnection
from src.socket.api.SocketAPI import SocketAPI
from src.utils.utility import encrypt_data, receive_data_into_buffer

FINISHED_FLAG_MASK = 0b10000000
HEADER_FINISHED_MASK = 0b01000000


class SecureSocketServer:
    def __init__(self, api: SocketAPI, host: str, port: str):
        # Initialize the SecureSocketServer with provided API, host, and port
        self.api: SocketAPI = api
        self.host: str = host
        self.port: str = port
        self.server_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_communication: SecureCommunication = SecureCommunication()
        self.connections = []
        self.running: bool = False
        self.server_thread: threading = None
        self.buffer: Queue = Queue(64)

    # Private Functions
    def __start(self):
        # Start the server and handle connections
        self.running = True
        try:
            # Create a new server socket, bind it, and start listening
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            # Create a thread to handle connections
            conn_thread = threading.Thread(target=self.handle_connection)
            conn_thread.start()
            conn_thread.join()
        except OSError as e:
            self.buffer.put(f"Error: {e}")
        except Exception as e:
            self.buffer.put(f"Unexpected error: {e}")
        self.running = False

    # Public Functions
    def start_server(self):
        """
        Start the server in a new thread.

        Returns:
            None
        """
        if not self.running:
            self.server_thread = threading.Thread(target=self.__start)
            self.server_thread.start()
            self.buffer.put(f"Starting Server")

    def end_service(self):
        # Shut down the server and close all connections
        self.running = False
        self.server_socket.shutdown(socket.SHUT_RDWR)
        self.server_socket.close()
        for conn in self.connections:
            conn.client_socket.shutdown(socket.SHUT_RDWR)
            conn.client_socket.close()
        self.server_thread.join()

    def get_messages(self):
        # Get all messages from the buffer
        messages = []
        while not self.buffer.empty():
            messages.append(self.buffer.get())
        return messages

    # Threaded Functions / Blocking
    def handle_connection(self):
        # Handle incoming connections
        while self.running:
            readable, _, _ = select.select([self.server_socket], [], [], 1)
            for readable_socket in readable:
                if readable_socket == self.server_socket and self.running:
                    # Accept the connection and perform handshake
                    connection, address = self.server_socket.accept()
                    secure_conn = self.handshake_connection(connection, address)
                    # Start a thread for reading from the connection
                    reading_thread = threading.Thread(target=self.reading,
                                                      kwargs={'secure_connection': secure_conn})
                    reading_thread.start()
                    if not self.buffer.full():
                        self.buffer.put(f"Accepted connection from {address}")

    # Utility
    def handshake_connection(self, conn, address) -> SecureConnection:
        # Handshake with the client
        conn.send((str(self.secure_communication.get_public_rsa_key()) + "\n").encode())
        data = self.read_asymmetric_encrypted_data(conn)
        recv_pub_key = rsa.PublicKey.load_pkcs1_openssl_pem(bytes(data))
        if not self.buffer.full():
            self.buffer.put(f"Accepted connection from {data}")
        # Store the connection
        secure_conn = SecureConnection(client_socket=conn, public_key=recv_pub_key, isAuthenticated=False,
                                       isRunning=True, username="", address=address)
        self.connections.append(secure_conn)
        return secure_conn

    def read_asymmetric_encrypted_data(self, socket: socket, segments: int) -> bytes:
        """
        Read asymmetrically encrypted data from the connection.

        Args:
            socket (socket): The socket from which to read data.
            segments (int): The number of segments to read.

        Returns:
            bytes: The decrypted asymmetrically encrypted data.
        """
        decrypted_data = bytearray()
        try:
            for _ in range(segments):
                encrypted_chunk = socket.recv(self.get_asymmetric_chunk_size())
                decrypted_chunk = self.decrypt_asymmetric_data(encrypted_chunk)
                decrypted_data.extend(decrypted_chunk)
            return bytes(decrypted_data)
        except Exception as e:
            self.buffer.put(f"Unexpected (read_asymmetric_encrypted_data) error: {e}")

    def get_asymmetric_chunk_size(self) -> int:
        """
        Get the size of each chunk for asymmetric encryption.

        Returns:
            int: The size of each chunk.
        """
        chunk_size_bits = self.secure_communication.get_public_rsa_key().n.bit_length()
        return chunk_size_bits // 8

    def decrypt_asymmetric_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt asymmetrically encrypted data.

        Args:
            encrypted_data (bytes): The encrypted data to decrypt.

        Returns:
            bytes: The decrypted data.
        """
        return self.secure_communication.asymmetric_decrypt_message(encrypted_data)

    def read_symmetric_encrypted_data(self, socket: socket, segments: int):
        # Read data from the connection
        data = bytearray(0)
        try:
            for _ in range(segments):
                encrypted_message = socket.recv(self.secure_communication.get_public_rsa_key().n.bit_length() // 8)
                decrypted_message = self.secure_communication.asymmetric_decrypt_message(encrypted_message)
                data.extend(decrypted_message)
            return data
        except Exception as e:
            self.buffer.put(f"Unexpected error: {e}")

    '''
        This function reads all incoming data and places it in a variable. To determine if the transmission has ended it will look for a section where 
    def read_until_EOT(self, socket, buffer_size=4096):
        # Read data from the connection
        data = bytearray(0)
        try:
            while True:
                data = socket.recv(buffer_size)
                if decrypted_message[0] == 0x04 and len(decrypted_message) == 1:
                    return file
                file.extend(decrypted_message)
        except Exception as e:
            self.buffer.put(f"Unexpected error: {e}")
    '''

    def read_num_of_header_segments_and_flags(self, socket: socket) -> (int, bytes):
        """
        Reads incoming data to extract the number of header segments and associated flags.

        :param socket: The socket from which to read the header data.
        :return: A tuple containing the number of segments and flags. (Type: (int, bytes))

        Note: This function is designed for RSA bit lengths of 2048 or greater.
        """
        try:
            # Check RSA bit length
            if self.secure_communication.get_public_rsa_key().n.bit_length() < 2048:
                raise ValueError("RSA bit length is too short for secure communication.")

            while True:
                # Receive and decrypt header
                encrypted_message = socket.recv(self.secure_communication.get_public_rsa_key().n.bit_length() // 8)
                decrypted_message = self.secure_communication.asymmetric_decrypt_message(encrypted_message)

                # Extract number of segments and flags
                num_of_segments_bytes = decrypted_message[:8]  # Size of a long
                decrypted_message = decrypted_message[8 + 1:]
                flags = decrypted_message[:1]  # 8 flags
                num_of_segments = struct.unpack('Q', num_of_segments_bytes)[0]  # Unpack as unsigned long long

                # Check if the finished flag is set
                if flags & HEADER_FINISHED_MASK:
                    return num_of_segments, flags

        except Exception as e:
            # Handle and log unexpected errors
            self.buffer.put(f"Unexpected error during header reading: {e}")

    def read_header_until_finished(self, socket: socket, segments: int) -> bytes:
        """
        Reads the header segments until the specified number is reached.

        :param socket: The socket from which to read the header data.
        :param segments: The number of header segments to read.
        :return: The concatenated header data. (Type: bytes)
        """
        try:
            data = bytearray()

            for _ in range(segments):
                encrypted_message = socket.recv(self.secure_communication.get_public_rsa_key().n.bit_length() // 8)

                # Check for socket closure
                if not encrypted_message:
                    raise ConnectionError("Socket closed unexpectedly")

                decrypted_message = self.secure_communication.asymmetric_decrypt_message(encrypted_message)
                data.extend(decrypted_message)

            return bytes(data)  # Convert to immutable bytes for consistency

        except socket.error as e:
            # Handle socket-related errors
            if e.errno == socket.errno.ECONNRESET:
                self.buffer.put("Connection reset by peer")
            else:
                self.buffer.put(f"Socket error: {e}")
        except struct.error as e:
            self.buffer.put(f"Error decoding struct: {e}")
        except Exception as e:
            # Handle and log unexpected errors
            self.buffer.put(f"Unexpected error during header reading: {e}")

    def parse_header(self, socket: socket, header_bytes: bytes) -> bytes:
        """
        Parse the header and determine the appropriate action for further data processing.

        Args:
            header_bytes (bytes): The header bytes containing information about the data.

        Returns:
            None
        """
        # Find the first delimiter to extract encryption type
        delimiter1 = header_bytes.index(0x03)
        encryption_type = header_bytes[:delimiter1].decode('utf-8')

        # Remove processed bytes
        header_bytes = header_bytes[delimiter1 + 1:]

        # Find the second delimiter to extract the number of segments
        delimiter2 = header_bytes.index(0x03)
        num_of_segments_bytes = header_bytes[:delimiter2]
        num_of_segments = struct.unpack('Q', num_of_segments_bytes)[0]  # Unpack as unsigned long long

        # Perform actions based on the encryption type
        if encryption_type == 'sym':
            self.buffer.put("Symmetrically Encrypted Message Type")
        elif encryption_type == 'asym':
            self.buffer.put("Asymmetrically Encrypted Message Type")
            return self.read_asymmetric_encrypted_data(socket, header_bytes)
        elif encryption_type == 'raw':
            self.buffer.put("Raw Message Type")
        else:
            self.buffer.put("Unknown Message Type. (Dropping)")

    # Called for each Connection
    def reading(self, secure_connection):
        # Read and handle incoming messages
        while secure_connection.isRunning and self.running:
            readable, _, _ = select.select([secure_connection.client_socket], [], [], 1)
            for readable_socket in readable:
                if readable_socket == secure_connection.client_socket and self.running:
                    header_data = self.read_header_until_finished(secure_connection.client_socket)
                    self.parse_header(header_data)

                    data = self.read_asymmetric_encrypted_data(secure_connection.client_socket)
                    if not self.buffer.full():
                        self.buffer.put(f"{data.decode('utf-8')}")
                    if data is None:
                        self.running = False
                        if not self.buffer.full():
                            self.buffer.put(f"Disconnected from {secure_connection.address}")
                    else:
                        self.api.req_handler(secure_connection, data)
