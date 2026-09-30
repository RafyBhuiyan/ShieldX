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
        top_frame = ctk.CTkFrame(tab, fg_color="transparent")
        top_frame.pack(fill="x", pady=(10, 5))

        ctk.CTkButton(
            top_frame,
            text="Choose Folder & Scan",
            height=38,
            font=("Segoe UI", 13, "bold"),
            command=self.start_scan
        ).pack(side="left", padx=(10, 10))

        self.select_all_btn = ctk.CTkButton(
            top_frame,
            text="Select All",
            width=90,
            command=self.select_all_threats,
            state="disabled"
        )
        self.select_all_btn.pack(side="left", padx=5)

        self.deselect_all_btn = ctk.CTkButton(
            top_frame,
            text="Deselect All",
            width=90,
            command=self.deselect_all_threats,
            state="disabled"
        )
        self.deselect_all_btn.pack(side="left", padx=5)

        self.progress = ctk.CTkProgressBar(tab, width=600)
        self.progress.set(0)
        self.progress.pack(pady=5)
        self.status = ctk.CTkLabel(tab, text="Ready to scan", font=("Segoe UI", 13))
        self.status.pack()

        # Scrollable frame for interactive threat items
        self.scan_results_frame = ctk.CTkScrollableFrame(tab, height=260)
        self.scan_results_frame.pack(fill="both", expand=True, padx=5, pady=8)

        self.scan_empty_label = ctk.CTkLabel(
            self.scan_results_frame,
            text="No scan has been run yet. Click 'Choose Folder & Scan' to begin.",
            text_color="gray"
        )
        self.scan_empty_label.pack(pady=40)

        # Bottom action buttons
        btn_frame = ctk.CTkFrame(tab, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(0, 5))

        self.quarantine_selected_btn = ctk.CTkButton(
            btn_frame,
            text="Quarantine Selected",
            fg_color="#e67e22",
            hover_color="#d35400",
            font=("Segoe UI", 13, "bold"),
            command=self.quarantine_selected,
            state="disabled"
        )
        self.quarantine_selected_btn.pack(side="right", padx=10)

        self.quarantine_all_btn = ctk.CTkButton(
            btn_frame,
            text="Quarantine All Threats",
            fg_color="#c0392b",
            hover_color="#962d22",
            font=("Segoe UI", 13, "bold"),
            command=self.quarantine_all,
            state="disabled"
        )
        self.quarantine_all_btn.pack(side="right", padx=5)

    def start_scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return
        self.clear_scan_results()
        self.progress.set(0)
        self.status.configure(text=f"Scanning folder: {os.path.basename(folder)}...")
        self.quarantine_selected_btn.configure(state="disabled")
        self.quarantine_all_btn.configure(state="disabled")
        self.select_all_btn.configure(state="disabled")
        self.deselect_all_btn.configure(state="disabled")
        threading.Thread(target=self.run_scan, args=(folder,), daemon=True).start()

    def clear_scan_results(self):
        for w in self.scan_results_frame.winfo_children():
            w.destroy()
        self.found = []

    def run_scan(self, folder):
        def prog(i, n, p):
            self.after(0, lambda: (self.progress.set(i / n),
                self.status.configure(text=f"Scanning {i}/{n}: {os.path.basename(p)}")))
        threats = scan_folder(folder, prog)
        self.after(0, self.show_results, threats)

    def show_results(self, threats):
        self.clear_scan_results()
        self.progress.set(1)
        if not threats:
            self.status.configure(text="✅ Scan complete — no threats found")
            ctk.CTkLabel(
                self.scan_results_frame,
                text="✅ Clean! No threats found in the scanned folder.",
                font=("Segoe UI", 14),
                text_color="#2ecc71"
            ).pack(pady=40)
            self.quarantine_selected_btn.configure(state="disabled")
            self.quarantine_all_btn.configure(state="disabled")
            self.select_all_btn.configure(state="disabled")
            self.deselect_all_btn.configure(state="disabled")
            return

        self.status.configure(text=f"⚠ {len(threats)} threat(s) found")
        self.quarantine_selected_btn.configure(state="normal")
        self.quarantine_all_btn.configure(state="normal")
        self.select_all_btn.configure(state="normal")
        self.deselect_all_btn.configure(state="normal")

        for path, name, method in threats:
            var = ctk.BooleanVar(value=True)
            row = ctk.CTkFrame(self.scan_results_frame)
            row.pack(fill="x", pady=3, padx=5)

            # Checkbox for selective picking
            chk = ctk.CTkCheckBox(row, text="", variable=var, width=24)
            chk.pack(side="left", padx=(8, 4))

            # Details
            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=6, pady=4)

            badge_color = "#e74c3c" if method == "Signature" else "#e67e22" if method == "Heuristic" else "#9b59b6"

            header_line = ctk.CTkFrame(info, fg_color="transparent")
            header_line.pack(fill="x", anchor="w")

            ctk.CTkLabel(
                header_line,
                text=f"[{method}]",
                font=("Segoe UI", 12, "bold"),
                text_color=badge_color
            ).pack(side="left", padx=(0, 6))

            ctk.CTkLabel(
                header_line,
                text=f"{name}  —  {os.path.basename(path)}",
                font=("Segoe UI", 12, "bold")
            ).pack(side="left")

            ctk.CTkLabel(
                info,
                text=path,
                font=("Segoe UI", 10),
                text_color="gray",
                anchor="w"
            ).pack(fill="x")

            entry = {
                "path": path,
                "name": name,
                "method": method,
                "var": var,
                "row": row
            }

            # Individual Quarantine button
            ctk.CTkButton(
                row,
                text="Quarantine",
                width=85,
                height=28,
                fg_color="#c0392b",
                hover_color="#962d22",
                command=lambda e=entry: self.quarantine_single(e)
            ).pack(side="right", padx=10, pady=6)

            self.found.append(entry)

    def select_all_threats(self):
        for e in self.found:
            e["var"].set(True)

    def deselect_all_threats(self):
        for e in self.found:
            e["var"].set(False)

    def quarantine_single(self, entry):
        path = entry["path"]
        name = entry["name"]
        if not os.path.exists(path):
            messagebox.showinfo("Notice", f"File already removed or not found:\n{path}")
            if entry in self.found:
                self.found.remove(entry)
            entry["row"].destroy()
            self._update_scan_state_after_action()
            return

        try:
            q.quarantine(path, name)
            entry["row"].destroy()
            if entry in self.found:
                self.found.remove(entry)
            self.refresh_quarantine()
            self._update_scan_state_after_action()
            messagebox.showinfo("Success", f"Quarantined:\n{os.path.basename(path)}")
        except OSError as e:
            messagebox.showerror("Error", f"Could not quarantine {path}:\n{e}")

    def quarantine_selected(self):
        selected = [e for e in self.found if e["var"].get()]
        if not selected:
            messagebox.showinfo("Notice", "No threats selected.\nCheck the box next to threats you want to quarantine.")
            return

        count = 0
        failed = 0
        for entry in selected:
            path = entry["path"]
            name = entry["name"]
            try:
                if os.path.exists(path):
                    q.quarantine(path, name)
                    count += 1
                entry["row"].destroy()
                if entry in self.found:
                    self.found.remove(entry)
            except OSError:
                failed += 1

        self.refresh_quarantine()
        self._update_scan_state_after_action()
        msg = f"{count} threat(s) moved to quarantine."
        if failed > 0:
            msg += f"\n{failed} file(s) could not be quarantined (file in use or locked)."
        messagebox.showinfo("Quarantine Completed", msg)

    def quarantine_all(self):
        if not self.found:
            return

        count = 0
        failed = 0
        for entry in list(self.found):
            path = entry["path"]
            name = entry["name"]
            try:
                if os.path.exists(path):
                    q.quarantine(path, name)
                    count += 1
                entry["row"].destroy()
                if entry in self.found:
                    self.found.remove(entry)
            except OSError:
                failed += 1

        self.refresh_quarantine()
        self._update_scan_state_after_action()
        msg = f"{count} threat(s) moved to quarantine."
        if failed > 0:
            msg += f"\n{failed} file(s) could not be quarantined."
        messagebox.showinfo("Quarantine All Completed", msg)

    def _update_scan_state_after_action(self):
        remaining = len(self.found)
        if remaining == 0:
            self.status.configure(text="✅ All detected threats have been handled")
            ctk.CTkLabel(
                self.scan_results_frame,
                text="✅ All detected threats have been quarantined.",
                font=("Segoe UI", 13),
                text_color="#2ecc71"
            ).pack(pady=40)
            self.quarantine_selected_btn.configure(state="disabled")
            self.quarantine_all_btn.configure(state="disabled")
            self.select_all_btn.configure(state="disabled")
            self.deselect_all_btn.configure(state="disabled")
        else:
            self.status.configure(text=f"⚠ {remaining} threat(s) remaining")
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