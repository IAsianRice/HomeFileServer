import base64
import errno
import socket
import threading
import time

import requests
from queue import Queue
from typing import Callable
import struct

import rsa
import select

from src.socket.SecureCommunication import SecureCommunication
from src.socket.SecureConnection import SecureConnection
from src.socket.api.SocketAPI import SocketAPI
from src.utils.DataReceiver import DataReceiver
from src.utils.utility import encrypt_data, receive_data_into_buffer


class SecureSocketServer:
    def __init__(self, api: SocketAPI, port: str):
        """
        Initialize the SecureSocketServer with the provided API, host, and port.

        Args:
            api (SocketAPI): The socket API used for handling requests.
            host (str): The host address to bind the server to.
            port (str): The port number to listen on.
        """
        self.api: SocketAPI = api
        self.server_name: str = ""
        self.host: str = ""
        self.public_ip_address: str = ""
        self.public_ipv4_address: str = ""
        self.port: str = port
        self.server_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.broadcasting_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.secure_communication: SecureCommunication = SecureCommunication()
        self.connections = []
        self.running: bool = False
        self.server_thread: threading = None
        self.broadcast_thread: threading = None
        self.buffer: Queue = Queue(64)

    def __start(self):
        """
        Start the server and handle connections.
        """

        self.public_ipv4_address = self.get_public_ipv4()
        self.public_ip_address = self.get_public_ip()
        self.host = self.get_local_ip()

        self.running = True
        self.broadcast_thread = threading.Thread(target=self.broadcast)
        self.broadcast_thread.start()
        try:
            # Create a new server socket, bind it, and start listening
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
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
        self.broadcast_thread.join()

    def broadcast(self):
        # Create a UDP socket for broadcasting
        self.broadcasting_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while self.running:
            # Broadcast the server's address
            message = f"MCSASR[{self.host}][{self.public_ipv4_address}][{self.port}][{self.server_name}]".encode("utf-8")
            self.broadcasting_socket.sendto(message, ('<broadcast>', 7001))

            # Wait for a while before broadcasting again

            time.sleep(1)

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
        """
        Shut down the server and close all connections.
        """
        self.running = False
        self.server_socket.shutdown(socket.SHUT_RDWR)
        self.server_socket.close()
        for conn in self.connections:
            conn.client_socket.shutdown(socket.SHUT_RDWR)
            conn.client_socket.close()
        self.server_thread.join()

    def get_messages(self):
        """
        Get all messages from the buffer.

        Returns:
            list: List of messages from the buffer.
        """
        messages = []
        while not self.buffer.empty():
            messages.append(self.buffer.get())
        return messages

    def handle_connection(self):
        """
        Handle incoming connections.
        """
        while self.running:
            readable, _, _ = select.select([self.server_socket], [], [], 1)
            for readable_socket in readable:
                if readable_socket == self.server_socket and self.running:
                    # Accept the connection and perform handshake
                    connection, address = self.server_socket.accept()
                    secure_connection = SecureConnection(
                        address=address,
                        client_socket=connection,
                        secure_communication=self.secure_communication,
                        log_buffer_callback=lambda: self.buffer.put(f"{address}:{secure_connection.log_buffer.get()}"),
                        on_stop_callback=lambda: self.connections.remove(secure_connection),
                    )

                    def req(req_num: int, data_recv: DataReceiver):
                        self.api.req_handler(secure_connection, req_num, data_recv)

                    secure_connection.request_handler = req
                    self.connections.append(secure_connection)
                    secure_connection.start()

                    # Start a thread for reading from the connection
                    if not self.buffer.full():
                        self.buffer.put(f"Accepted connection from {address}")

    def get_public_ip(self):
        try:
            # Use an external service to get the public IP
            response = requests.get('https://api64.ipify.org?format=json')

            # Extract the public IP from the response
            public_ip = response.json()['ip']

            return public_ip
        except requests.RequestException as e:
            print(f"Error: {e}")


    def get_public_ipv4(self):
        try:
            # Use ipinfo.io to get the public IPv4 address
            response = requests.get('https://ipinfo.io/ip')

            # Extract the IPv4 address from the response
            public_ipv4 = response.text.strip()

            return public_ipv4
        except requests.RequestException as e:
            print(f"Error: {e}")

    def get_local_ip(self):
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # Connect to a dummy address to get the local IP
            s.connect(("8.8.8.8", 80))

            # Get the local IP address
            local_ip = s.getsockname()[0]

            return local_ip
        except socket.error as e:
            print(f"Error: {e}")
        finally:
            s.close()
