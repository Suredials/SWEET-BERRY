"""Single-consumer event queue. HTTP and sensors share this boundary."""
import queue
import threading


class EventBus:
    def __init__(self, engine):
        self.engine = engine
        self.queue = queue.Queue(maxsize=1000)
        self.stop = threading.Event()
        self.error = ''
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                event = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.engine.ingest(event)
            except Exception as exc:
                self.error = str(exc)
            finally:
                self.queue.task_done()
