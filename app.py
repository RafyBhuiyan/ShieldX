import os, threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from scanner import scan_file, scan_folder
import quarantine as q
from monitor import RealTimeMonitor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ShieldX Antivirus")
        self.geometry("850x580")
        self.monitor = None
        self.found = []
        ctk.CTkLabel(self, text="🛡 ShieldX Antivirus",font=("Segoe UI", 26, "bold")).pack(pady=12)
        tabs = ctk.CTkTabview(self)
        tabs.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.build_scan(tabs.add("Scan"))
        self.build_realtime(tabs.add("Real-Time Protection"))
        self.build_quarantine(tabs.add("Quarantine"))
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------- Scan tab ----------------
    def build_scan(self, tab):
        ctk.CTkButton(tab, text="Choose Folder & Scan", height=40,command=self.start_scan).pack(pady=10)
        self.progress = ctk.CTkProgressBar(tab, width=600)
        self.progress.set(0)
        self.progress.pack(pady=5)
        self.status = ctk.CTkLabel(tab, text="Ready")
        self.status.pack()
        self.results = ctk.CTkTextbox(tab, height=250)
        self.results.pack(fill="both", expand=True, pady=10)
        ctk.CTkButton(tab, text="Quarantine All Threats", fg_color="#c0392b",command=self.quarantine_all).pack(pady=5)

    def start_scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.results.delete("1.0", "end")
        self.found = []
        self.progress.set(0)
        threading.Thread(target=self.run_scan, args=(folder,), daemon=True).start()

    def run_scan(self, folder):
        def prog(i, n, p):
            self.after(0, lambda: (self.progress.set(i / n),
                self.status.configure(text=f"Scanning {i}/{n}: {os.path.basename(p)}")))
        threats = scan_folder(folder, prog)
        self.after(0, self.show_results, threats)

    def show_results(self, threats):
        self.found = threats
        self.progress.set(1)
        if not threats:
            self.status.configure(text="✅ Scan complete — no threats found")
            self.results.insert("end", "No threats found.\n")
            return
        self.status.configure(text=f"⚠ {len(threats)} threat(s) found")
        for path, name, method in threats:
            self.results.insert("end", f"[{method}] {name}\n   {path}\n\n")

    def quarantine_all(self):
        count = 0
        for path, name, _ in self.found:
            try:
                if os.path.exists(path):
                    q.quarantine(path, name)
                    count += 1
            except OSError as e:
                self.results.insert("end", f"Could not quarantine {path}: {e}\n")
        self.results.insert("end", f"\n{count} file(s) moved to quarantine.\n")
        self.found = []
        self.refresh_quarantine()

    # ---------------- Real-time tab ----------------
    # ---------------- Real-time tab ----------------
    def build_realtime(self, tab):
        default = os.path.join(os.path.expanduser("~"), "Downloads")
        self.watch_path = ctk.StringVar(value=default)
        ctk.CTkLabel(tab, text="Folder to protect:").pack(pady=(10, 0))

        path_frame = ctk.CTkFrame(tab, fg_color="transparent")
        path_frame.pack(pady=5)
        self.watch_entry = ctk.CTkEntry(path_frame, textvariable=self.watch_path, width=420)
        self.watch_entry.pack(side="left", padx=(0, 8))
        self.browse_btn = ctk.CTkButton(path_frame, text="Browse", width=80, command=self.browse_watch_path)
        self.browse_btn.pack(side="left")

        self.rt_switch = ctk.CTkSwitch(tab, text="Real-Time Protection",
                                       command=self.toggle_rt)
        self.rt_switch.pack(pady=10)
        self.rt_log = ctk.CTkTextbox(tab, height=300)
        self.rt_log.pack(fill="both", expand=True, pady=10)

    def browse_watch_path(self):
        initial = self.watch_path.get().strip()
        if not os.path.isdir(initial):
            initial = os.path.expanduser("~")
        folder = filedialog.askdirectory(initialdir=initial)
        if folder:
            self.watch_path.set(folder)

    def toggle_rt(self):
        watch_dir = self.watch_path.get().strip()
        if self.rt_switch.get():
            if not os.path.isdir(watch_dir):
                self.rt_switch.deselect()
                messagebox.showerror("Error", f"Folder does not exist:\n{watch_dir}")
                return
            try:
                self.monitor = RealTimeMonitor(watch_dir, self.on_new_file)
                self.monitor.start()
                self.log(f"🟢 Protection ON — watching {watch_dir}")
            except Exception as e:
                self.rt_switch.deselect()
                messagebox.showerror("Error", f"Cannot watch folder:\n{e}")
        else:
            if self.monitor:
                self.monitor.stop()
                self.monitor = None
            self.log("🔴 Protection OFF")

    def on_new_file(self, path):
        abs_path = os.path.abspath(path)
        abs_qdir = os.path.abspath(q.QDIR)
        # Prevent scanning files within quarantine directory or missing files
        if os.path.normcase(abs_path).startswith(os.path.normcase(abs_qdir)) or not os.path.exists(abs_path):
            return

        result = scan_file(abs_path)
        if result:
            name, method = result
            quarantined = False
            try:
                quarantined = q.quarantine(abs_path, name)
            except OSError:
                quarantined = False
            self.after(0, self.alert, abs_path, name, method, quarantined)
        else:
            self.after(0, self.log, f"✔ Clean: {os.path.basename(abs_path)}")

    def alert(self, path, name, method, quarantined=True):
        if quarantined:
            self.log(f"⚠ THREAT BLOCKED [{method}] {name} → {os.path.basename(path)}")
            self.refresh_quarantine()
            messagebox.showwarning("ShieldX — Threat Detected!",
                f"Threat: {name}\nMethod: {method}\nFile: {path}\n\nFile has been quarantined.")
        else:
            self.log(f"⚠ THREAT DETECTED [{method}] {name} → {os.path.basename(path)} (Quarantine pending/locked)")
            messagebox.showwarning("ShieldX — Threat Detected!",
                f"Threat: {name}\nMethod: {method}\nFile: {path}\n\nWarning: Threat detected, but file could not be quarantined immediately (file may be open in another application).")

    def log(self, msg):
        self.rt_log.insert("end", msg + "\n")
        self.rt_log.see("end")

    # ---------------- Quarantine tab ----------------
    def build_quarantine(self, tab):
        ctk.CTkButton(tab, text="Refresh", command=self.refresh_quarantine).pack(pady=5)
        self.qframe = ctk.CTkScrollableFrame(tab)
        self.qframe.pack(fill="both", expand=True, pady=5)
        self.refresh_quarantine()

    def refresh_quarantine(self):
        for w in self.qframe.winfo_children():
            w.destroy()
        items = q.list_items()
        if not items:
            ctk.CTkLabel(self.qframe, text="Quarantine is empty").pack(pady=20)
            return
        for it in items:
            row = ctk.CTkFrame(self.qframe)
            row.pack(fill="x", pady=3, padx=5)
            ctk.CTkLabel(row, anchor="w",
                text=f"{it['threat']}  |  {os.path.basename(it['original'])}  |  {it['time']}"
            ).pack(side="left", padx=10, fill="x", expand=True)
            ctk.CTkButton(row, text="Delete", width=70, fg_color="#c0392b",
                command=lambda i=it["id"]: self.q_action(q.delete, i)).pack(side="right", padx=4)
            ctk.CTkButton(row, text="Restore", width=70,
                command=lambda i=it["id"]: self.q_action(q.restore, i)).pack(side="right", padx=4)

    def q_action(self, fn, qid):
        fn(qid)
        self.refresh_quarantine()

    def on_close(self):
        if self.monitor:
            self.monitor.stop()
        self.destroy()

if __name__ == "__main__":
    App().mainloop()