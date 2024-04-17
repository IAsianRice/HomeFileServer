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
                    secure_connection = SecureConnection(address=address,
                                                         client_socket=connection,
                                                         secureCommunication=self.secure_communication,
                                                         log_buffer_callback=lambda:
                                                         self.buffer.put(f"{address}:{secure_connection.log_buffer.get()}"),
                                                         on_stop_callback=lambda:
                                                         self.connections.remove(secure_connection),
                                                         on_data_recv_callback=lambda x:
                                                         self.api.req_handler(secure_connection, x)
                                                         )
                    self.connections.append(secure_connection)
                    secure_connection.start()

                    # Start a thread for reading from the connection
                    if not self.buffer.full():
                        self.buffer.put(f"Accepted connection from {address}")
