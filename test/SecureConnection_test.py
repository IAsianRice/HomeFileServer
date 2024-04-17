import base64
import struct
import threading

import select
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.socket.SecureCommunication import SecureCommunication
from src.socket.SecureConnection import SecureConnection
from src.utils.DataReceiver import DataReceiver

import unittest
from unittest.mock import Mock, patch, call

PEM_RSAPrivateKey = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAhsnlMAqOYVww
oEz8ovjVxxQsWLQYu7bjPQEVIwXA9qAbCAlBIZFexX9mo0VqzFnfkrKxNvYMyUl+
V6/fvJGu7MT1Vhd9rIR1xqBxd4V0h+GOUZL6NpoMFB7Bvir9n0uND9+/PgpeeC+B
1mCoti9PRSUfPKhd01NoiHDd0xKkVvZmjH2/ug55j0bhCdbE4C3ZmH3ksXdExJhI
EHAhQMpyb9d49dN3hxpPM0EzTtY+oebSalaU2gz/hpSj1q+LosL2LUNMto5l3uLk
NH9IRTWNxbSQ9YzcybJQGNggTJyX2lzcqwOC0V70vuUgksqL03dlt/4bOLN2VcN6
3a5JdMFdAgMBAAECggEAUY8IKloOrsBZ4JOX6ZJUnaNnTV4KdUvYLy2hrsWWY2dW
7fyahwfkYGSEEwPpnVOSYx7vKhmhZEtFIgudiseEY7kTuubMrsWNm6MYRtkeJP6H
M9Yk0HCfE6zWVrbr2WNJCyoFXCu5EsoRPgyGCBKduhQNpMz6ejzS4b6jKaWICSu9
lqeyG3g5fBu0AxeldWMXJZvPGf+hi9XCayad0RxbObBnH85fFEvbIF/Mku8NzOBq
ihXCEkC0INnlF6IFOKWDOlmFxsY3sI++v4SbovLunhIGAJPxmUzyx3XeeMxjeJS5
q/nu28kqLs8o/B9pUPercQbLDYOdNK44BL/w4rhiNQKBgQDnVAoRDrb6QBYYjCof
8bspD8y/0UiWVRPI8gPhUuVhYlfyhnOvvjUCc4sExVfakT1B+zL+ObbJBucZEyam
eJhQNyHGo0GyZM2rAA/znXnS/6HXUCFEAd0zSU6OPzgGbw01i/h69JA+2CHEzQ1u
XGOka518CF4OuF754CRUuQBV8wKBgQDVD1gVmTW2H0GwPyvIE6iA/yOjijIjaitM
TtHNcjq6eUxOw7UrScHt/jVmPVZPsItxD4jktRJCNs79QvatmycuhaWkEcETOu8D
36Ydxsitk5Vv/5eCCn1KlV34owsfmOXrKSlrikLzkzW78eLm8nycGNDzw7uI5sM6
G+QOI/DPbwKBgQDJYcrlsJawYuwZcKQXbRyPEZcggfQcE3KG49Fm7gCMd82yb0P1
AbQqLyYeACKMPxZCA4oP8XRjqyOyG47xK1kFtAkuYN+HiuPU8tfwL+5nNm3RAIwF
JU5JII9HnFeMmk64h+LIP3H3k7ZKGmyP39RKxfiyiqI/VFgyVeOq8ecN6wKBgDfJ
dL7zBuVQ+do0MDqLKyvbonFH1ij/u6aXXMf2iPoamKhnBiD3hxfR4BmNJfRnvZs0
/hskbkt4HmqiBgUfAvtjcyOqomtumvbgsJZLXnBUnGRfAETEilnlEl3wExGK72jL
tlS6Nx2gBgnYJBlklMwqk0vAjHIkOioU83ngX0VxAoGAYD0hPfAGz/426VJWS6a7
kwbEgJgXBdJhKDZm/QT5f++qIgTzk6lhfIVc94enz+LQP3UeVJwUf+/lEbcJuRVl
zvF7vRo1nJsfR+jxBmYreWUdrdQk5ImzTlwBZ+9UtA1OQPwHM9mxMliDX4w7OCG6
c4nbnZyApLLKXUZFYc3/DVM=
-----END PRIVATE KEY-----"""

PEM_RSAPublicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwIbJ5TAKjmFcMKBM/KL4
1ccULFi0GLu24z0BFSMFwPagGwgJQSGRXsV/ZqNFasxZ35KysTb2DMlJflev37yR
ruzE9VYXfayEdcagcXeFdIfhjlGS+jaaDBQewb4q/Z9LjQ/fvz4KXngvgdZgqLYv
T0UlHzyoXdNTaIhw3dMSpFb2Zox9v7oOeY9G4QnWxOAt2Zh95LF3RMSYSBBwIUDK
cm/XePXTd4caTzNBM07WPqHm0mpWlNoM/4aUo9avi6LC9i1DTLaOZd7i5DR/SEU1
jcW0kPWM3MmyUBjYIEycl9pc3KsDgtFe9L7lIJLKi9N3Zbf+GzizdlXDet2uSXTB
XQIDAQAB
-----END PUBLIC KEY-----"""

symmetric_key = """CEwYgK778p18ehEhqabeWsTlW1Fm8VcSyRE2/YpXHl4="""

LargeTestData = """Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras dignissim quis erat consequat 
pretium. Quisque ante sem, condimentum ut sapien vel, lobortis scelerisque odio. Aliquam erat volutpat. Morbi 
venenatis pharetra justo vel sodales. Vestibulum viverra eros eget ligula bibendum commodo. Vestibulum rhoncus mollis 
mi, at fermentum mauris efficitur nec. Nam blandit ipsum eget nunc ultricies vestibulum. Mauris ut vestibulum neque. 
Curabitur a sem placerat lorem mollis aliquet. Vivamus elementum dui id turpis eleifend fermentum. Ut massa magna, 
fringilla malesuada felis in, molestie tincidunt odio. Nam nec lacinia nunc, quis dapibus tellus. Vivamus rutrum, 
ligula id vestibulum egestas, orci ligula sagittis tellus, vel facilisis elit purus ut mauris. Vivamus vel arcu 
aliquet, fringilla lorem in, porttitor libero. Suspendisse odio purus, aliquet sit amet volutpat ut, convallis ut 
justo. Donec sed faucibus mi, ac venenatis est. Sed imperdiet varius auctor. Nullam efficitur imperdiet nibh, 
non porttitor lectus tristique a. Aenean ac tellus ante. Etiam ac vulputate nulla, et tempus erat. Etiam malesuada 
consectetur ex. Fusce vel consectetur odio. Cras ultrices metus id tortor pharetra fringilla. Ut ut felis quis ante 
pretium consequat. Sed molestie viverra mi non fringilla. Phasellus vehicula arcu ac aliquam tincidunt. Aenean 
malesuada, ligula ut bibendum sodales, neque quam varius sem, sed finibus justo nisi vel massa. Aenean pellentesque 
laoreet ullamcorper. Phasellus fermentum vulputate molestie. Cras scelerisque tincidunt magna at cursus. Cras 
malesuada sem ut vestibulum feugiat. Nunc tincidunt ipsum quis interdum rhoncus. Praesent pharetra pellentesque odio 
vitae porttitor. In bibendum ligula et tortor mollis posuere. Quisque vestibulum eu mauris id lobortis. Mauris 
venenatis malesuada orci at sollicitudin. Duis dui purus, fringilla non tortor sed, sollicitudin vulputate tortor. 
Suspendisse potenti. Suspendisse tellus turpis, viverra in rhoncus at, consequat at tellus. Sed vitae eros quam. 
Aenean eget ante libero. Vivamus eget diam tristique ante placerat suscipit a a libero. Sed semper at ante lacinia 
egestas. Suspendisse eu venenatis nunc, ac rutrum ex. Donec maximus iaculis metus, id aliquam sapien sagittis ac. Sed 
et leo ullamcorper, dapibus dolor sollicitudin, iaculis neque. Morbi maximus risus sit amet justo pellentesque, 
non egestas tortor blandit. Donec tempor dictum finibus. Maecenas a tincidunt dolor. Fusce sit amet sapien malesuada, 
faucibus sapien eu, accumsan massa. Curabitur ac nibh ullamcorper, volutpat dolor sed, euismod libero. Etiam nec nunc 
ac purus dapibus tempus. Praesent at ipsum feugiat, tempus velit placerat, dictum enim. Integer tellus lectus, 
scelerisque in vehicula ut, fringilla id libero. Donec pulvinar dui tempor euismod lacinia. Proin elementum blandit 
orci vitae pulvinar. Quisque gravida fermentum lorem, non fermentum velit tincidunt in. Nam feugiat nisl est, 
at scelerisque ipsum ornare a. Vivamus fringilla eros nec elit dapibus, tempor lacinia libero placerat. Pellentesque 
ut ante nulla. Nullam ultricies lacus risus. Mauris suscipit risus at nulla tempor pellentesque."""


def formatted_asymmetric_message(key: RSAPublicKey, data: bytes, transmission_id: int = 0, flags: int = 0b00000000, encryption_method: int = 1, request_num: int = 0):
    # Determine the chunk size based on the key size
    message_header_encrypted = bytearray()
    chunk_size = (key.key_size // 8) - 11
    message_body_encrypted = bytearray()
    body_chunks = 0
    encrypted_body_chunk_list = []
    body_chunk_list = []

    for i in range(0, len(data), chunk_size):
        end_index = min(i + chunk_size, len(data))
        chunk = data[i:end_index]
        body_chunk_list.append(chunk)
        encrypted_chunk = key.encrypt(chunk, asymmetric_padding.PKCS1v15())
        message_body_encrypted.extend(encrypted_chunk)
        encrypted_body_chunk_list.append(encrypted_chunk)
        body_chunks += 1
    message_header = struct.pack('<BQQBQ', flags, transmission_id, body_chunks, encryption_method, request_num)
    message_header_encrypted += key.encrypt(message_header, asymmetric_padding.PKCS1v15())
    return message_header_encrypted, message_body_encrypted, encrypted_body_chunk_list, message_header, data, body_chunk_list


class TestSecureConnection(unittest.TestCase):
    def setUp(self):
        # Set up a mock SecureCommunication object for testing
        secure_communication = SecureCommunication(PEM_RSAPrivateKey.encode('utf-8'), PEM_RSAPublicKey.encode('utf-8'), symmetric_key)

        public_pem = PEM_RSAPublicKey
        self.server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())

        # Set up a mock socket for testing
        client_socket = Mock()

        # Mock the request_handler function for testing
        def mock_request_handler(request, data_receiver):
            data_receiver.push_data(b'decrypted_data')
            data_receiver.set_message_number(42)

        self.secure_connection = SecureConnection(
            client_socket=client_socket,
            secure_communication=secure_communication,
            address="test_address",
            log_buffer_callback=Mock(),
            on_stop_callback=Mock(),
            on_data_recv_callback=Mock(),
            request_handler=mock_request_handler
        )

    def test_log(self):
        self.secure_connection.log_buffer = Mock()
        self.secure_connection.log_buffer_callback = Mock()

        # The Test
        self.secure_connection.log("Test message")

        self.secure_connection.log_buffer.put.assert_called_once_with("Test message")
        self.secure_connection.log_buffer_callback.assert_called_once()

    def test_stop(self):
        self.secure_connection.socket = Mock()
        self.secure_connection.reading_thread = Mock()

        # The Test
        self.secure_connection.stop()

        self.assertTrue(self.secure_connection.socket.close.called)
        self.assertFalse(self.secure_connection.running)

        self.secure_connection.reading_thread.join.assert_called_once()

    def test_start(self):
        self.secure_connection.handshake_connection = Mock()
        self.secure_connection.reading_thread = Mock()
        threading.Thread = Mock()

        # The Test
        self.secure_connection.start()

        self.secure_connection.handshake_connection.assert_called_once()
        threading.Thread.assert_called_once_with(target=self.secure_connection.reading)
        self.secure_connection.reading_thread.start.assert_called_once()

    def test_start_exception(self):
        self.secure_connection.stop = Mock()
        self.secure_connection.handshake_connection = Mock(side_effect=Exception("Test Exception"))

        # The Test
        self.secure_connection.start()

        self.secure_connection.stop.assert_called_once()

    '''def test_start_reading_exception(self):
        self.secure_connection.stop = Mock()
        self.secure_connection.reading = Mock(side_effect=Exception("Test Exception"))

        # The Test
        self.secure_connection.start()
        
        self.secure_connection.stop.assert_called_once()'''

    def test_handshake_connection(self):
        # Mock necessary dependencies
        self.secure_connection.read_header = Mock()
        self.secure_connection.parse_header = Mock()
        self.secure_connection.send_asymmetric_encrypted_formatted_message = Mock()
        self.secure_connection.secure_communication.get_public_rsa_key_pem = Mock()
        self.secure_connection.secure_communication.get_symmetric_key_bytes = Mock()

        self.secure_connection.secure_communication.get_public_rsa_key_pem.return_value = PEM_RSAPublicKey.encode('utf-8')
        encrypted_header, encrypted_body, _, header, data, _ = formatted_asymmetric_message(self.server_public_k, PEM_RSAPublicKey.encode('utf-8'))
        self.secure_connection.read_header.return_value = header
        self.secure_connection.parse_header.return_value = (0, Mock())  # Mock DataReceiver
        symmetric_key_bytes = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the derived key
            salt=b'salt_value_here',
            iterations=100000,  # Adjust the number of iterations based on your security requirements
            backend=default_backend()
        ).derive(base64.b64decode(symmetric_key))
        self.secure_connection.secure_communication.get_symmetric_key_bytes.return_value = symmetric_key_bytes
        self.secure_connection.secure_communication.symmetric_key_iv = b'fake_iv'

        self.secure_connection.socket.send = Mock()

        # Call the handshake_connection method
        self.secure_connection.handshake_connection()

        # Assert that the socket.send method was called with the expected argument
        expected_send_argument = PEM_RSAPublicKey.encode('utf-8') + b'\x04'
        self.secure_connection.socket.send.assert_called_once_with(expected_send_argument)

        # Assert that read_header, parse_header, and send_asymmetric_encrypted_formatted_message were called
        self.secure_connection.read_header.assert_called_once()
        self.secure_connection.parse_header.assert_called_once_with(header)
        self.secure_connection.send_asymmetric_encrypted_formatted_message.assert_called_once_with(
            base64.b64encode(symmetric_key_bytes) + b'\x03fake_iv'
        )

    def test_get_client_key_handler(self):
        mock_data_receiver = Mock()
        self.secure_connection.get_client_key_handler(mock_data_receiver)
        mock_data_receiver.set_receiver_function.assert_called_once()

    def test_reading(self):
        self.secure_connection.read_header = Mock()
        self.secure_connection.parse_header = Mock()
        self.secure_connection.request_handler = Mock()

        # Mock necessary dependencies
        self.secure_connection.running = True
        self.secure_connection.socket_buffer.inUse = False
        self.secure_connection.read_header.return_value = b'fake_header_data'
        self.secure_connection.parse_header.return_value = (42, Mock())  # Mock DataReceiver

        # Call the reading method
        self.secure_connection._reading()

        # Assert that read_header, parse_header, and request_handler were called
        self.secure_connection.read_header.assert_called_once()
        self.secure_connection.parse_header.assert_called_once_with(b'fake_header_data')

    def test_read_header_and_asymmetric_decrypter(self):
        encrypted_header, encrypted_body, _, header, data, _ = formatted_asymmetric_message(self.server_public_k, PEM_RSAPublicKey.encode('utf-8'))
        self.secure_connection.socket_buffer = Mock()
        self.secure_connection.socket_buffer.recv.return_value = encrypted_header

        header_data = self.secure_connection.read_header()

        self.assertTrue(self.secure_connection.socket_buffer.recv.called)
        self.assertEqual(header_data, header)

    def test_parse_header_request_not_streamed(self):
        self.secure_connection.socket_buffer = Mock()

        encrypted_header, _, encrypted_body_chunks, header, _, data_chunks = formatted_asymmetric_message(self.server_public_k, PEM_RSAPublicKey.encode('utf-8'), 1)
        self.secure_connection.socket_buffer.recv.return_value = encrypted_body_chunks[0]

        def check_request_handler(t_id, data_recv: DataReceiver):
            data_recv = Mock()
            data_recv.push_raw.assert_called_once_with(encrypted_body_chunks[0])
            self.assertEqual(1, t_id)
        self.secure_connection.request_handler = check_request_handler

        self.secure_connection.parse_header(header)


    def test_parse_header_intermittent(self):
        # Mock DataReceiver to simulate its behavior
        self.secure_connection.socket_buffer = Mock()
        mock_data_receiver = Mock()
        encrypted_header, _, encrypted_body_chunks, header, _, data_chunks = formatted_asymmetric_message(
            self.server_public_k, PEM_RSAPublicKey.encode('utf-8'), 1, 0b00000001,1,1)
        self.secure_connection.socket_buffer.recv.return_value = encrypted_body_chunks[0]

        # Set the mock_data_receiver as the value of self.transmission_streams[transmission_id]
        transmission_id = 1  # Replace with the actual transmission_id used in your test
        with patch.object(self.secure_connection, 'transmission_streams', {transmission_id: mock_data_receiver}):
            # Mock other dependencies or set up necessary conditions

            # Call the method you want to test
            self.secure_connection.parse_header(header)

            # Assert that the methods of the mock_data_receiver were called as expected
            mock_data_receiver.set_message_number.assert_called_once_with(1)
            mock_data_receiver.push_raw.assert_called_once_with(encrypted_body_chunks[0])
            # Add more assertions based on your code logic


    def test_parse_header_req_then_intermittent(self):
        self.secure_connection.socket_buffer = Mock()
        mock_data_receiver = Mock()

        encrypted_header, _, encrypted_body_chunks, header, _, data_chunks = formatted_asymmetric_message(
            self.server_public_k, PEM_RSAPublicKey.encode('utf-8'), 1, 0b00000010)
        self.secure_connection.socket_buffer.recv.return_value = encrypted_body_chunks[0]

        def check_request_handler(t_id, data_recv: DataReceiver):
            data_recv = Mock()
            data_recv.push_raw.assert_called_once_with(encrypted_body_chunks[0])
            self.assertEqual(1, t_id)
        self.secure_connection.request_handler = check_request_handler

        self.secure_connection.parse_header(header)

        encrypted_header, _, encrypted_body_chunks, header, _, data_chunks = formatted_asymmetric_message(
            self.server_public_k, PEM_RSAPublicKey.encode('utf-8'), 1, 0b00000001,1,1)
        self.secure_connection.socket_buffer.recv.return_value = encrypted_body_chunks[0]

        transmission_id = 1  # Replace with the actual transmission_id used in your test
        with patch.object(self.secure_connection, 'transmission_streams', {transmission_id: mock_data_receiver}):
            # Mock other dependencies or set up necessary conditions

            # Call the method you want to test
            self.secure_connection.parse_header(header)

            # Assert that the methods of the mock_data_receiver were called as expected
            mock_data_receiver.set_message_number.assert_called_once_with(1)
            mock_data_receiver.push_raw.assert_called_once_with(encrypted_body_chunks[0])
            # Add more assertions based on your code logic

    def test_parse_header_exception(self):
        self.secure_connection.stop = Mock()
        header_data = b'invalid_header_data'
        self.secure_connection.parse_header(header_data)
        self.secure_connection.stop.assert_called_once()


if __name__ == '__main__':
    unittest.main()
