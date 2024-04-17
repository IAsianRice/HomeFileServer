import base64
import secrets
import struct
import threading
from dataclasses import dataclass
import socket
from queue import Queue
from typing import Callable

import os

import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.utils.SecureStreamBuffer import SecureStreamBuffer
from src.utils.SocketBuffer import SocketBuffer
from src.utils.utility import encrypt_bytes_data, encrypt_with_public_key

HEADER_FINISHED_MASK = 0b01000000


class SecureCommunication:
    def __init__(self):

        if not os.path.isfile("./key/public.pem") and not os.path.isfile("./key/private.pem"):
            # Generate a new RSA private key
            self.server_private_k = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Get the corresponding public key
            self.server_public_k = self.server_private_k.public_key()

            # Serialize the private key to PEM format
            self.private_pem = self.server_private_k.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            # Serialize the public key to PEM format
            self.public_pem = self.server_public_k.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open("./key/public.pem", "wb") as f:
                f.write(self.public_pem)
            with open("./key/private.pem", "wb") as f:
                f.write(self.private_pem)
        else:
            with open("./key/public.pem", "rb") as f:
                self.public_pem = f.read()
                self.server_public_k = serialization.load_pem_public_key(self.public_pem, backend=default_backend())
            with open("./key/private.pem", "rb") as f:
                self.private_pem = f.read()
                self.server_private_k = serialization.load_pem_private_key(self.private_pem, password=None,
                                                                           backend=default_backend())
            # Generate a symmetric key
        self.symmetric_key = base64.b64encode(os.urandom(32)).decode('utf-8')

        # Parse the symmetric key into bytes
        symmetric_key_bytes = base64.b64decode(self.symmetric_key)

        # Create a key derivation function (KDF) to derive a key from the given symmetric key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the derived key
            salt=b'salt_value_here',
            iterations=100000,  # Adjust the number of iterations based on your security requirements
            backend=default_backend()
        )

        # Derive the key for encryption and decryption using the KDF
        self.symmetric_key_bytes = kdf.derive(symmetric_key_bytes)
        self.symmetric_key_iv = os.urandom(16)

        # Create AES encryption and decryption ciphers
        '''cipher = Cipher(algorithms.AES(self.symmetric_key_bytes), modes.CFB(self.symmetric_key_iv), backend=default_backend())
        symmetric_key_encrypt_cipher = cipher.encryptor()
        symmetric_key_decrypt_cipher = cipher.decryptor()'''

    def symmetric_encrypt_data(self, data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.symmetric_key_bytes), modes.CFB(self.symmetric_key_iv), backend=default_backend())
        ciphertext = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return ciphertext

    def symmetric_decrypt_data(self, encrypted_data: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(self.symmetric_key_bytes), modes.CFB(self.symmetric_key_iv), backend=default_backend())
        plaintext = cipher.decryptor().update(encrypted_data) + cipher.decryptor().finalize()
        return plaintext

    def get_public_rsa_key(self) -> RSAPublicKey:
        return self.server_public_k

    def get_public_rsa_key_pem(self):
        return self.public_pem

    def get_symmetric_key(self) -> str:
        return self.symmetric_key


    def get_symmetric_key_bytes(self) -> bytes:
        return self.symmetric_key_bytes


    def asymmetric_decrypt_message(self, encrypted_message: bytes) -> bytes:
        return self.server_private_k.decrypt(
            bytes(encrypted_message),
            asymmetric_padding.PKCS1v15())

    ''',
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )'''

    def get_asymmetric_chunk_size(self) -> int:
        """
        Get the size of each chunk for asymmetric encryption.

        Returns:
            int: The size of each chunk.a
        """
        chunk_size_bits = self.get_public_rsa_key().key_size
        return chunk_size_bits // 8


'''
@dataclass
class SecureConnection:
    client_socket: socket
    public_key: rsa.PublicKey
    isAuthenticated: bool
    isRunning: bool
    username: str
    address: str
'''

'''
Information Layout: [Header_Segments & flags (Asym Encrypted)][Header(Asym Encrypted)][Body(Encryption Specified in Header)]
Header Layout: [Encryption_Method, Body_Segments]

'''


class SecureConnection:
    def __init__(self, client_socket: socket,
                 secureCommunication: SecureCommunication,
                 address: str,
                 log_buffer_callback: Callable,
                 on_stop_callback: Callable,
                 on_data_recv_callback: Callable[[SecureStreamBuffer], None]):
        self.socket: socket = client_socket
        self.socket_buffer: SocketBuffer = SocketBuffer(client_socket)
        self.secure_communication: SecureCommunication = secureCommunication
        self.client_pub_key: RSAPublicKey | None = None
        self.log_buffer: Queue = Queue(64)
        self.running: bool = True
        self.address: str = address
        self.log_buffer_callback: Callable = log_buffer_callback
        self.on_stop_callback: Callable = on_stop_callback
        self.on_data_recv_callback: Callable[[SecureStreamBuffer], None] = on_data_recv_callback
        self.reading_thread: threading.Thread | None = None

    def log(self, message):
        self.log_buffer.put(message)
        self.log_buffer_callback()
        pass

    def stop(self):
        self.socket.close()
        self.running = False
        if not (self.reading_thread is None):
            self.reading_thread.join()
        self.on_stop_callback()
        pass

    def start(self):
        try:
            self.handshake_connection()  # server initiates handshake
            self.reading_thread = threading.Thread(target=self.reading)
            self.reading_thread.start()
            #self.log(f"Starting Connection")
        except Exception as e:
            self.log(f"Unexpected (start) error: {e}")

    def handshake_connection(self):
        try:
            # Send Pub Key
            #self.log(f"Sending Public Key")
            self.socket.send(self.secure_communication.get_public_rsa_key_pem() + b'\x04')

            # Get Client Pub Key
            #self.log(f"Receiving Client Pub Key")
            header_data = self.read_header()
            data = self.parse_header(header_data).read_until_end()
            #self.log(data)
            #self.log(data.decode('utf-8'))
            self.client_pub_key = serialization.load_pem_public_key(bytes(data), backend=default_backend())

            # Send Symmetric Key
            #self.log(f"Sending Symmetric Key")
            self.send_asymmetric_encrypted_formatted_message(
                base64.b64encode(self.secure_communication.get_symmetric_key_bytes()) + b'\x03' + self.secure_communication.symmetric_key_iv)

        except Exception as e:
            self.log(f"Unexpected (handshake_connection) error: {e}")

    # Called for each Connection
    '''def reading(self):
        # Read and handle incoming messages
        try:
            while self.running:
                readable, _, _ = select.select([self.socket], [], [], 1)
                for readable_socket in readable:
                    if readable_socket == self.socket and self.running:

                        header_data = self.read_header()
                        data = self.parse_header(header_data)
                        if not self.log_buffer.full():
                            self.log(f"received command: {data.decode('utf-8')}")
                        if data is None:
                            self.running = False
                            if not self.log_buffer.full():
                                self.log(f"Disconnected from {self.address}")
                        else:
                            self.on_data_recv_callback(data)

        except Exception as e:
            self.log(f"Unexpected (reading) error: {e}")
            self.stop()'''


    def reading(self):
        # Read and handle incoming messages
        try:
            while self.running:
                readable, _, _ = select.select([self.socket], [], [], 1)
                for readable_socket in readable:
                    if readable_socket == self.socket and self.running and not self.socket_buffer.inUse:
                        print(self.socket_buffer.inUse)
                        header_data = self.read_header()
                        buffer = self.parse_header(header_data)
                        self.on_data_recv_callback(buffer)

        except Exception as e:
            self.log(f"Unexpected (reading) error: {e}")
        self.stop()

    def read_header(self):
        """
        Reads and decrypts the header from the client socket.

        Returns:
            bytes: The decrypted header data.
        """
        try:
            #self.log(f"Unexpected (read_header) error: 1")
            chunk_size = self.secure_communication.get_asymmetric_chunk_size()
            buffer = self.socket_buffer.recv(chunk_size)

            #self.log(f"Unexpected (read_header) error: 2")
            #self.socket.recv_into(buffer)

            #self.log(f"Unexpected (read_header) error: {buffer}")
            #self.log(f"Unexpected (read_header) error: 3")
            header_size = self.secure_communication.asymmetric_decrypt_message(buffer)

            #self.log(f"Unexpected (read_header) error: 4")
            segments = struct.unpack('<Q', header_size[:8])[0]

            #self.log(f"Unexpected (read_header) error: 5")
            header = bytearray()
            for _ in range(segments):
                buffer = self.socket_buffer.recv(chunk_size)
                header += self.secure_communication.asymmetric_decrypt_message(buffer)

            #self.log(f"Unexpected (read_header) error: 6")
            return bytes(header)
        except Exception as e:
            self.log(f"Unexpected (read_header) error: {e}")
            self.stop()

    def parse_header(self, header: bytes) -> SecureStreamBuffer:
        """
        Parses the header and decrypts the body from the client socket.

        Args:
            header (bytes): Header of Message

        Returns:
            bytes: The decrypted body data.
        """
        try:
            #self.log(f"Unexpected (parse_header) error: 1")
            encryption_method, body_segments = struct.unpack('<BQ', header[:9])

            #self.log(f"Unexpected (parse_header) error: 2")

            #self.log(f"Unexpected (parse_header) error: 3")
            '''
            body = bytearray()
            if encryption_method == 0x01:
                chunk_size = self.secure_communication.get_asymmetric_chunk_size()
                buffer = bytearray(chunk_size)
                for _ in range(body_segments):
                    self.socket.recv_into(buffer)
                    body += self.secure_communication.asymmetric_decrypt_message(buffer)
            elif encryption_method == 0x02:
                chunk_size = 2048
                #buffer = bytearray(8192)
                while b'\x04' not in body:
                    buffer = self.socket.recv(16384)
                    body += buffer
                    #self.log(buffer.decode('utf-8'))
                body = body[:body.index(b'\x04')]
                #print(body.decode('utf-8'))
                self.log("Beginning File Save")
                decoded = base64.b64decode(body)
                self.log("Decoded")
                body = self.secure_communication.symmetric_decrypt_data(decoded)
                self.log("Decrypted")
            elif encryption_method == 0x03:
                while b'\x04' not in body:
                    buffer = self.socket.recv(16384)
                    body += buffer
                body = body[:body.index(b'\x04')]
                #print(body.decode('utf-8'))
                self.log("Beginning File Save")
                decoded = base64.b64decode(body)
                self.log("Decoded")
                body = self.secure_communication.symmetric_decrypt_data(decoded)
                self.log("Decrypted")

            #self.log(f"Unexpected (parse_header) error: 4")
            return bytes(body)
            '''
            if encryption_method == 0x01:
                chunk_size = self.secure_communication.get_asymmetric_chunk_size()
                return SecureStreamBuffer(socket_buffer=self.socket_buffer,
                                          chunk_size=chunk_size,
                                          cipher_function=self.secure_communication.asymmetric_decrypt_message,
                                          segments=body_segments)
            elif encryption_method == 0x02:
                chunk_size = body_segments
                return SecureStreamBuffer(socket_buffer=self.socket_buffer,
                                          chunk_size=chunk_size,
                                          cipher_function=self.secure_communication.symmetric_decrypt_data,
                                          delimiter=bytes([0x04]))

        except Exception as e:
            self.log(f"Unexpected (parse_header) error: {e}")
            self.stop()

    def send_asymmetric_encrypted_formatted_message(self, data: bytes):
        """
        Encrypts and formats a message using asymmetric encryption with RSA.

        Args:
            data (bytes): The input data to be encrypted.

        Returns:
            bytes: The encrypted and formatted message.
        """

        # Determine the chunk size based on the key size
        chunk_size = (self.client_pub_key.key_size // 8) - 11
        complete_message = bytearray()
        header_chunks = 1
        message_header = bytearray()
        body_chunks = 0
        message_body = bytearray()

        # Encrypt data in chunks and build the message body
        for i in range(0, len(data), chunk_size):
            end_index = min(i + chunk_size, len(data))
            chunk = data[i:end_index]
            encrypted_chunk = encrypt_with_public_key(self.client_pub_key, chunk)
            message_body.extend(encrypted_chunk)
            body_chunks += 1

        # Encrypt the message header and assemble the complete message
        message_header += encrypt_with_public_key(self.client_pub_key, b'\x01' + struct.pack('<Q', body_chunks))

        complete_message += encrypt_with_public_key(self.client_pub_key, struct.pack('<Q', header_chunks)
                                                    ) + message_header + message_body

        self.socket.send(bytes(complete_message))

    def send_symmetric_encrypted_formatted_message(self, data: bytes):
        """
        Encrypts and formats a message using symmetric encryption with RSA key exchange.

        Args:
            data (bytes): The input data to be encrypted.

        Returns:
            bytes: The encrypted and formatted message.
        """

        complete_message = bytearray()
        header_chunks = 1
        message_header = bytearray()
        body_chunks = 0

        # Encrypt the data using symmetric key encryption and encode in base64
        cipherText = self.secure_communication.symmetric_encrypt_data(data)
        #self.log(cipherText)
        #self.log(base64.b64encode(cipherText))
        message_body = base64.b64encode(cipherText)
        #self.log(self.secure_communication.symmetric_decrypt_data(cipherText))

        # Encrypt the message header and assemble the complete message
        message_header += encrypt_with_public_key(self.client_pub_key, b'\x02' + struct.pack('<Q', body_chunks))

        complete_message += encrypt_with_public_key(self.client_pub_key, struct.pack('<Q', header_chunks)
                                        ) + message_header + message_body + b'\x04'

        self.socket.send(bytes(complete_message))
