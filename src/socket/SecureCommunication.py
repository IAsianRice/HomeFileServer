import base64
import secrets
import struct
import threading
from dataclasses import dataclass
import socket
from queue import Queue
from typing import Callable, Union

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
    def __init__(self, private_key_pem: Union[bytes, None] = None, public_key_pem: Union[bytes, None] = None, symmetric_key: Union[str, None] = None):
        if private_key_pem is not None and public_key_pem is not None:
            self.private_pem = private_key_pem
            self.public_pem = public_key_pem
            self.server_public_k = serialization.load_pem_public_key(self.public_pem, backend=default_backend())
            self.server_private_k = serialization.load_pem_private_key(self.private_pem, password=None,
                                                                       backend=default_backend())
        elif not os.path.isfile("./key/public.pem") and not os.path.isfile("./key/private.pem"):
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

        if symmetric_key is not None :
            self.symmetric_key = symmetric_key
            symmetric_key_bytes = base64.b64decode(symmetric_key)
        else:
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
        return self.server_private_k.decrypt(bytes(encrypted_message), asymmetric_padding.PKCS1v15())

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

