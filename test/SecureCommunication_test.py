import base64
import os
import unittest

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.socket.SecureCommunication import SecureCommunication

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

EmptyTestData = """"""

SingularTestData = """a"""

NormalTestData = """Hello this is an encrypted Message"""

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


class SecureCommunicationTest(unittest.TestCase):
    def setUp(self):
        self.secure_communication = SecureCommunication(PEM_RSAPrivateKey.encode('utf-8'), PEM_RSAPublicKey.encode('utf-8'), symmetric_key)

    def test_symmetric_encryption_empty_data(self):
        encrypted_data = self.secure_communication.symmetric_encrypt_data(EmptyTestData.encode('utf-8'))
        decrypted_data = self.secure_communication.symmetric_decrypt_data(encrypted_data).decode('utf-8')
        self.assertEqual(EmptyTestData, decrypted_data)
        pass

    def test_symmetric_encryption_singular_data(self):
        encrypted_data = self.secure_communication.symmetric_encrypt_data(SingularTestData.encode('utf-8'))
        decrypted_data = self.secure_communication.symmetric_decrypt_data(encrypted_data).decode('utf-8')
        self.assertEqual(SingularTestData, decrypted_data)
        pass

    def test_symmetric_encryption_normal_data(self):
        encrypted_data = self.secure_communication.symmetric_encrypt_data(NormalTestData.encode('utf-8'))
        decrypted_data = self.secure_communication.symmetric_decrypt_data(encrypted_data).decode('utf-8')
        self.assertEqual(NormalTestData, decrypted_data)
        pass

    def test_symmetric_encryption_large_data(self):
        encrypted_data = self.secure_communication.symmetric_encrypt_data(LargeTestData.encode('utf-8'))
        decrypted_data = self.secure_communication.symmetric_decrypt_data(encrypted_data).decode('utf-8')
        self.assertEqual(LargeTestData, decrypted_data)
        pass

    def test_get_public_rsa_key(self):
        self.assertEqual(self.secure_communication.get_public_rsa_key(), serialization.load_pem_public_key(PEM_RSAPublicKey.encode('utf-8'), backend=default_backend()))
        pass

    def test_get_public_rsa_key_pem(self):
        self.assertEqual(self.secure_communication.get_public_rsa_key_pem().decode('utf-8'), PEM_RSAPublicKey)
        pass

    def test_get_symmetric_key(self):
        self.assertEqual(self.secure_communication.get_symmetric_key(), symmetric_key)
        pass

    def test_get_symmetric_key_bytes(self):
        symmetric_key_bytes = base64.b64decode(symmetric_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Length of the derived key
            salt=b'salt_value_here',
            iterations=100000,  # Adjust the number of iterations based on your security requirements
            backend=default_backend()
        )

        # Derive the key for encryption and decryption using the KDF
        self.assertEqual(self.secure_communication.get_symmetric_key_bytes(), kdf.derive(symmetric_key_bytes))
        pass

    def test_asymmetric_encryption_empty_data(self):
        public_pem = PEM_RSAPublicKey
        server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        data = server_public_k.encrypt(EmptyTestData.encode('utf-8'), asymmetric_padding.PKCS1v15())
        self.assertEqual(self.secure_communication.asymmetric_decrypt_message(data).decode('utf-8'), EmptyTestData)

        pass

    def test_asymmetric_encryption_singular_data(self):
        public_pem = PEM_RSAPublicKey
        server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        data = server_public_k.encrypt(SingularTestData.encode('utf-8'), asymmetric_padding.PKCS1v15())
        self.assertEqual(self.secure_communication.asymmetric_decrypt_message(data).decode('utf-8'), SingularTestData)

        pass

    def test_asymmetric_encryption_normal_data(self):
        public_pem = PEM_RSAPublicKey
        server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        data = server_public_k.encrypt(NormalTestData.encode('utf-8'), asymmetric_padding.PKCS1v15())
        self.assertEqual(self.secure_communication.asymmetric_decrypt_message(data).decode('utf-8'), NormalTestData)

        pass

    def test_asymmetric_encryption_large_data(self):
        public_pem = PEM_RSAPublicKey
        server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        chunk_size = (server_public_k.key_size // 8) - 11
        encrypted_chunk_size = (server_public_k.key_size // 8)
        data = LargeTestData.encode('utf-8')
        message_body = bytearray()
        body_chunks = 0

        for i in range(0, len(data), chunk_size):
            end_index = min(i + chunk_size, len(data))
            chunk = data[i:end_index]
            encrypted_chunk = server_public_k.encrypt(chunk, asymmetric_padding.PKCS1v15())
            message_body.extend(encrypted_chunk)
            body_chunks += 1

        final_message = ""
        for i in range(0, len(message_body), encrypted_chunk_size):
            end_index = min(i + encrypted_chunk_size, len(message_body))
            chunk = message_body[i:end_index]
            decrypted_chunk = self.secure_communication.asymmetric_decrypt_message(chunk).decode('utf-8')
            final_message += decrypted_chunk
        self.assertEqual(final_message, LargeTestData)

        pass

    def test_get_asymmetric_chunk_size(self):
        private_pem = PEM_RSAPrivateKey
        public_pem = PEM_RSAPublicKey
        server_public_k = serialization.load_pem_public_key(public_pem.encode('utf-8'), backend=default_backend())
        server_private_k = serialization.load_pem_private_key(private_pem.encode('utf-8'), password=None,
                                                                   backend=default_backend())

        self.assertEqual((server_public_k.key_size // 8), self.secure_communication.get_asymmetric_chunk_size())
        pass


if __name__ == '__main__':
    unittest.main()
