import time
import unittest
import unittest
from queue import Queue
from unittest.mock import Mock

from src.utils.DataReceiver import DataReceiver


class TestDataReceiver(unittest.TestCase):
    def setUp(self):
        # Create a DataReceiver instance for testing
        self.data_receiver = DataReceiver()

    def test_get_all_data_prior(self):
        print("setting recv func")

        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'), True)

        self.finished = False

        def _(dr: DataReceiver):
            self.assertEqual("So PainSo PainSo PainSo Pain", dr.get_data_until_terminated().decode('utf-8'))
            print("got data")
            self.finished = True

        self.data_receiver.start_receiver_function(_)

        while not self.finished:
            pass

    def test_get_all_data_staggered(self):
        print("setting recv func")

        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))

        self.finished = False

        def _(dr: DataReceiver):
            self.assertEqual("So PainSo PainSo PainSo Pain", dr.get_data_until_terminated().decode('utf-8'))
            print("got data")
            self.finished = True

        self.data_receiver.start_receiver_function(_)

        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'), True)
        while not self.finished:
            pass

    def test_get_all_data(self):
        print("setting recv func")

        self.finished = False

        def _(dr: DataReceiver):
            self.assertEqual("So PainSo PainSo PainSo Pain", dr.get_data_until_terminated().decode('utf-8'))
            print("got data")
            self.finished = True

        self.data_receiver.start_receiver_function(_)
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("So Pain".encode('utf-8'), True)

        while not self.finished:
            pass

    def test_get_all_data_and_some_error(self):
        with self.assertRaises(Exception):
            print("setting recv func")

            self.finished = False

            def _(dr: DataReceiver):
                dr.get_data_until_terminated().decode('utf-8')
                print("got data")
                self.finished = True

            self.data_receiver.start_receiver_function(_)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'))
            time.sleep(1)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'))
            time.sleep(1)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'))
            time.sleep(1)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'), True)
            time.sleep(1)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'))
            time.sleep(1)
            print("sending data")
            self.data_receiver.push_data("So Pain".encode('utf-8'))

            while not self.finished:
                pass

    def test_get_until_delimiter(self):
        print("setting recv func")

        def _(dr: DataReceiver):
            username = dr.get_data_until_delimiter(b'\x03').decode('utf-8')
            print("got username")
            password = dr.get_data_until_delimiter(b'\x03').decode('utf-8')
            print("got password")
            self.assertEqual("SuperMario", username)
            self.assertEqual("Bros:SuperLuigiEdition", password)

        self.data_receiver.start_receiver_function(_)
        print("sending data")
        self.data_receiver.push_data("Super".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("Mario".encode('utf-8') + b'\x03' + "Bros:SuperLui".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("giEdition".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data(b'\x03', True)

    def test_multiple_recv_func_error(self):
        with self.assertRaises(Exception):

            def _(dr: DataReceiver):
                dr.get_data_until_delimiter(b'\x03').decode('utf-8')
                print("got username")
                dr.get_data_until_delimiter(b'\x03').decode('utf-8')
                print("got password")

            def _2(dr: DataReceiver):
                dr.get_data_until_terminated().decode('utf-8')
                print("got data")

            self.data_receiver.start_receiver_function(_)
            self.data_receiver.start_receiver_function(_2)

    def test_stream_data(self):
        print("setting recv func")

        self.finished = False
        self.mock_file = ""

        def _(dr: DataReceiver):
            def _(data: bytes):
                print(data.decode('utf-8'))
                self.mock_file += data.decode('utf-8')
            dr.stream_data_until_terminated_into(_)
            self.finished = True

        self.data_receiver.start_receiver_function(_)
        print("sending data")
        self.data_receiver.push_data("Super".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("Mario".encode('utf-8') + b'\x03' + "Bros:SuperLui".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data("giEdition".encode('utf-8'))
        time.sleep(1)
        print("sending data")
        self.data_receiver.push_data(b'\x03', True)

        while not self.finished:
            pass

        self.assertEqual("SuperMario\x03Bros:SuperLuigiEdition\x03", self.mock_file)

    def test_multiple_recv_func_error_2(self):
        with self.assertRaises(Exception):
            self.mock_file = ""

            def _(dr: DataReceiver):
                def _(data: bytes):
                    print(data.decode('utf-8'))
                    self.mock_file += data.decode('utf-8')
                dr.stream_data_until_terminated_into(_)

            def _2(dr: DataReceiver):
                dr.get_data_until_terminated().decode('utf-8')
                print("got data")

            self.data_receiver.start_receiver_function(_)
            self.data_receiver.start_receiver_function(_2)

            print("sending data")
            self.data_receiver.push_data("Super".encode('utf-8'))
            time.sleep(1)

if __name__ == '__main__':
    unittest.main()
