import threading

class CountingSemaphore:
    def __init__(self, initial_count):
        self._count = initial_count
        self._lock = threading.Lock()
        self._condition = threading.Condition(lock=self._lock)

    def acquire(self):
        with self._lock:
            while self._count == 0:
                self._condition.wait()
            self._count -= 1

    def release(self, permits=1):
        with self._lock:
            self._count += permits
            self._condition.notify_all()


class CountingDownSemaphore:
    def __init__(self, count_cap):
        self._count = 0
        self._count_cap = count_cap
        self._lock = threading.Lock()
        self._condition = threading.Condition(lock=self._lock)

    def acquire(self):
        with self._lock:
            while self._count == 0:
                self._condition.wait()
            self._count -= 1

    def release(self):
        with self._lock:
            if self._count < self._count_cap:
                self._count += 1
                self._condition.notify_all()

