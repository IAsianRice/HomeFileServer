import json
import os
import secrets

import bcrypt
import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from rsa import PublicKey



def read_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            # Load JSON data from the file
            data = json.load(file)
            return data
    except FileNotFoundError:
        # print(f"Error: File not found - {file_path}")
        return None
    except json.JSONDecodeError:
        # print(f"Error: Unable to decode JSON in the file - {file_path}")
        return None
    except Exception as e:
        # print(f"Error occurred: {e}")
        return None


def write_json_file(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)


def encrypt_data(public_key, data: str) -> bytes:
    # Encrypt data using the public key
    ciphertext = rsa.encrypt(data.encode('utf-8'), public_key)
    return ciphertext


'''def encrypt_bytes_data(public_key, data: bytes) -> bytes:
    # Encrypt data using the public key
    ciphertext = rsa.encrypt(data, public_key)
    return ciphertext'''


def encrypt_bytes_data(public_key: PublicKey, data: bytes) -> (int, bytes):
    chunk_size = (public_key.n.bit_length() // 8) - 11
    # Initialize an empty byte array to hold the complete encrypted message
    complete_message = b""

    segments = 0

    # Encrypt and send data in chunks
    for i in range(0, len(data), chunk_size):
        # Calculate the endIndex for the current chunk
        end_index = min(i + chunk_size, len(data))

        # Extract the chunk of data to be encrypted
        chunk = data[i:end_index]

        # Encrypt the chunk using the server's public key
        encrypted_chunk = rsa.encrypt(chunk, public_key)

        # Concatenate the encrypted chunk to the complete message
        complete_message += encrypted_chunk

        segments += 1



    # Append an End of Transmission (EOT) marker to the complete message
    complete_message += rsa.encrypt(b'\x04', public_key)

    # Log the complete encrypted message (for debugging purposes)
    # print(complete_message.decode('utf-8'))

    # Send the complete encrypted message to the server (replace this with your actual send data to server logic)
    # send_data_to_server(complete_message)
    return segments, complete_message

def encrypt_with_public_key(public_key, plaintext: bytes):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.PKCS1v15()
    )
    return ciphertext
def hash_password(password) -> bytes:
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def verify_password(input_password: bytes, hashed_password: bytes):
    # Check if the input password matches the hashed password
    return bcrypt.checkpw(input_password, hashed_password)


def __create_directory_structure(directory):
    result = {"name": os.path.basename(directory), "type": "Directory", "content": []}

    for entry in os.listdir(directory):
        entry_path = os.path.join(directory, entry)

        if os.path.isdir(entry_path):
            result["content"].append(__create_directory_structure(entry_path))
        elif os.path.isfile(entry_path):
            file_info = {
                "name": entry,
                "type": "File",
                "extension": os.path.splitext(entry)[1][1:],  # Extract the file extension
                "size": os.path.getsize(entry_path)  # Get the file size in bytes
            }
            result["content"].append(file_info)

    return result


def get_directory_structure(directory):
    if os.path.exists(directory) and os.path.isdir(directory):
        return __create_directory_structure(directory)
    else:
        return {"error": "Invalid directory path"}


def create_user_directory(directory_name):
    parent_dir = f"./usersDir/"

    path = os.path.join(parent_dir, directory_name)

    if not os.path.exists(path):
        os.mkdir(path)
        return {"output": "Created Successfully"}
    else:
        return {"error": "Invalid directory path"}


def create_file(path, data):  # assumes you have the extention in the name
    parent_dir = f"./usersDir/"

    path = os.path.join(parent_dir, path)

    fo = open(path, "wb")
    fo.write(data)
    fo.close()
    return {"output": "Created Successfully"}
    # print('Received successfully! New filename is:', path)


def receive_data_into_buffer(sock, buffer_size=1024):
    buffer = b''  # Use bytes for binary data

    while True:
        data = sock.recv(buffer_size)
        if not data:
            # Break the loop if no more data is received
            break

        # Append the received data to the buffer
        buffer += data

    return buffer
