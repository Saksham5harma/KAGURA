import threading
import queue


class EventBus:

    def __init__(self):
        self.listeners = []
        self.queue = queue.Queue()
        self.lock = threading.Lock()

    def subscribe(self, callback):
        with self.lock:
            self.listeners.append(callback)

    def emit(self, event_type, data):

        event = {
            "type": event_type,
            "data": data
        }

        self.queue.put(event)

        with self.lock:
            for listener in self.listeners:
                try:
                    listener(event)
                except Exception:
                    pass

    def clear(self):
        with self.lock:
            self.listeners = []


BUS = EventBus()
