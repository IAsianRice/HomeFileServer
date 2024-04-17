import threading
from queue import Queue
from typing import Callable, Union

from src.utils.Semaphores import CountingDownSemaphore


class DataReceiver:
    """
    DataReceiver class facilitates the reception and processing of data.

    Whenever data is pushed into the DataReceiver, it triggers a callback and provides the callback with the data.
    """

    def __init__(self):
        self._terminated: bool = False
        self._recv_func_thread: threading = None
        self._buffer: bytearray = bytearray()
        self._state_updated_semaphore = CountingDownSemaphore(1)

        self._exception_raised: bool = False
        self._exception_reason: str = ""

    # data change Reliant
    def _get_data(self) -> bytes:
        ret_val = self._buffer
        self._buffer = bytearray()
        return ret_val

    '''def get_data(self, size: int) -> bytes:
        if size > len(self.over_buffer):
            self.over_buffer += self._get_data()
        ret_val = self.over_buffer[:size]
        self.over_buffer = self.over_buffer[size + 1:]
        return ret_val'''

    # State change Reliant
    def get_data_until_terminated(self) -> bytes:
        while not self._terminated:
            self._state_updated_semaphore.acquire()
            if self._exception_raised:
                raise Exception(self._exception_reason)

        ret_val = self._buffer
        self._buffer = bytearray()
        return ret_val

    def get_data_until_delimiter(self, delimiter: bytes) -> bytes:
        while delimiter not in self._buffer:
            self._state_updated_semaphore.acquire()
            if self._exception_raised:
                raise Exception(self._exception_reason)

        ret_val = self._buffer[:self._buffer.index(delimiter)]
        self._buffer = self._buffer[self._buffer.index(delimiter) + 1:]
        return ret_val

    def stream_data_until_terminated_into(self, function: Callable[[bytes], None]):
        while not self._terminated:
            self._state_updated_semaphore.acquire()
            function(self._get_data())
            if self._exception_raised:
                raise Exception(self._exception_reason)

    # State changers
    def push_data(self, data: bytes, finished: bool = False):
        self._buffer += data
        if self._terminated:
            self._terminated = True
            self._exception_reason = "Adding Data to an already terminated DR is undefined behaviour"
            self._exception_raised = True
            raise Exception(self._exception_reason)

        if finished:
            self.terminate()
        else:
            self._state_updated_semaphore.release()  # state changed

    def start_receiver_function(self, function: Callable[['DataReceiver'], None]):
        if self._recv_func_thread is None:
            self._recv_func_thread = threading.Thread(target=function, args=(self,))
            self._recv_func_thread.start()
        else:
            self._terminated = True
            self._exception_reason = "2 Receiver Functions ran! (Only one can be ran)"
            self._exception_raised = True
            self._recv_func_thread.join()
            raise Exception(self._exception_reason)

        self._state_updated_semaphore.release()  # state changed

    def terminate(self):
        self._terminated = True

        self._state_updated_semaphore.release()  # state changed

        if self._recv_func_thread is not None:
            self._recv_func_thread.join()
