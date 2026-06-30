import asyncio
from collections import defaultdict


class EventBus:

    def __init__(self):

        self.subscribers = defaultdict(list)

    def subscribe(self, event_type, callback):

        self.subscribers[event_type].append(callback)

    def emit(self, event_type, data):

        if event_type in self.subscribers:

            for callback in self.subscribers[event_type]:
                try:
                    callback(data)
                except Exception:
                    pass

    def broadcast(self, event_type, message):

        self.emit(event_type, message)
