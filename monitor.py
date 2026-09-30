import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class _Handler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
    def on_created(self, event):
        if not event.is_directory:
            self.callback(event.src_path)
    def on_moved(self, event):          # e.g. browser download finishing
        if not event.is_directory:
            self.callback(event.dest_path)

class RealTimeMonitor:
    def __init__(self, folder, on_file):
        self.folder, self.on_file, self.observer = folder, on_file, None

    def _wrap(self, path):
        time.sleep(0.5)                 # wait until the file is fully written
        self.on_file(path)

    def start(self):
        self.observer = Observer()
        self.observer.schedule(_Handler(self._wrap), self.folder, recursive=True)
        self.observer.start()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()