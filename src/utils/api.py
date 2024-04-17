"""
Server API calls
"""
import rsa


def api_file_download(input, connection):
    if input == 1:
        # get the file name length
        fileNameLength = int.from_bytes(connection.recv(64), "little")
        # get the file name
        fileName = connection.recv(fileNameLength).decode()
        # get the file length
        fileLength = int.from_bytes(connection.recv(4), "little")

        # Creating a new file at server end and writing the data
        fo = open(fileName, "wb")
        data = connection.recv(fileLength)
        fo.write(data)
        fo.close()
        print('Received successfully! New filename is:', fileName)
    else:
        pass


def api_upload_file(input, connection):
    if input == 2:
        pass
    else:
        pass


def api_debug_message(input, connection):
    if input == 3:
        message = rsa.decrypt(connection.recv(2048), self.private_key)
        print(message)
    else:
        pass


def api_message(input, connection):
    if input == 4:
        pass
    else:
        pass


def api_message_to(input, connection):
    if input == 5:
        pass
    else:
        pass







