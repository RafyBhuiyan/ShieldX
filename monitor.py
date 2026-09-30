import os
import threading
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class _Handler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.schedule_scan(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.schedule_scan(event.src_path)

    def on_moved(self, event):          # e.g. browser download finishing, file rename
        if not event.is_directory:
            self.monitor.schedule_scan(event.dest_path)

class RealTimeMonitor:
    def __init__(self, folder, on_file, debounce_delay=0.35):
        self.folder = os.path.abspath(folder)
        self.on_file = on_file
        self.debounce_delay = debounce_delay
        self.observer = None
        self._timers = {}
        self._lock = threading.Lock()
        self._running = False

    def schedule_scan(self, path):
        if not self._running:
            return
        norm_path = os.path.abspath(path)
        with self._lock:
            # Cancel any pending timer for this file to debounce rapid save/write events
            if norm_path in self._timers:
                self._timers[norm_path].cancel()
            timer = threading.Timer(self.debounce_delay, self._process_file, args=(norm_path,))
            self._timers[norm_path] = timer
            timer.daemon = True
            timer.start()

    def _process_file(self, path):
        with self._lock:
            self._timers.pop(path, None)

        if not self._running:
            return

        if not os.path.exists(path) or not os.path.isfile(path):
            return

        # Ensure the file write is completed and file is accessible
        if not self._wait_file_stable(path):
            return

        try:
            self.on_file(path)
        except Exception:
            pass

    def _wait_file_stable(self, path, max_wait=1.5, check_interval=0.08):
        """Wait until the file write is finished and released by the writer application."""
        start_time = time.time()
        while time.time() - start_time < max_wait:
            if not self._running or not os.path.exists(path):
                return False
            try:
                # Attempt to open file to verify read access and that it's not exclusively locked
                with open(path, "rb") as f:
                    _ = f.read(512)
                return True
            except (PermissionError, OSError):
                time.sleep(check_interval)
        return os.path.exists(path)

    def start(self):
        self._running = True
        self.observer = Observer()
        self.observer.schedule(_Handler(self), self.folder, recursive=True)
        self.observer.start()

    def stop(self):
        self._running = False
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2.0)
            except Exception:
                pass
            self.observer = None