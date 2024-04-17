"""
Server
"""
import socket
import string

import select
import threading
import rsa
from src.utils.api import api_file_download, api_debug_message


class Server:
    def __init__(self, port, exp, mod, private_key):
        self.host: string = ""
        self.port: int = port
        self.public_key_e = exp
        self.public_key_n = mod
        self.private_key = private_key
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []

    def reading(self, conn):
        while self.running:
            encrypted_message = conn.recv(2048)
            decrypted_message = int.from_bytes(rsa.decrypt(encrypted_message, self.private_key), "little")
            # print(f"Received and decrypted message: {decrypted_message.decode()}")

            api_file_download(decrypted_message, conn)
            api_debug_message(decrypted_message, conn)

    def connection(self):
        while self.running:
            readable, _, _ = select.select([self.server], [], [], 5)
            if self.running:
                if readable:
                    # accept incoming connections
                    connection, address = self.server.accept()
                    connection.send(str(self.public_key_e).encode())
                    connection.send(str(self.public_key_n).encode())
                    # append the connection to a list
                    self.connections.append(connection)

                    reading_thread = threading.Thread(target=self.reading, kwargs={'conn': connection})
                    reading_thread.start()
                    print(f"Accepted connection from {address}")

        print("Thread Finished")

    def writing(self):
        while self.running:
            i = input()
            print(i)
            if i == "quit":
                print("I QUIT!")
                self.server.close()
                self.running = False
            for c in self.connections:
                c.send(i.encode());

        print("Thread Finished")

    def start(self):
        self.server.bind(("10.0.0.141", 7000))
        self.server.listen(10)
        print(f"Listening for connections on :{7000}")

        conn_thread = threading.Thread(target=self.connection)
        writing_thread = threading.Thread(target=self.writing)
        conn_thread.start()
        writing_thread.start()
        conn_thread.join()
        writing_thread.join()






