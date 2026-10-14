# XZZ/DZKJ Exporter by CE.

# A standalone Windows desktop program that captures and exports documents opened in DZKJ.

from __future__ import annotations

import argparse
import configparser
import ctypes
import hashlib
import ntpath
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from pcb import Chunk, PCBError, decode_positioned_file, decode_stream_file, repair_file

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.ini"
CONFIG = configparser.ConfigParser()
CONFIG.read(CONFIG_PATH, encoding="utf-8-sig")

DEFAULT_DZKJ = Path(CONFIG.get(
    "DZKJ", "DZKJ_PATH", fallback=r"C:\Program Files (x86)\DZKJ\DZKJ.exe"
))
_AGENT_SETTING = Path(CONFIG.get("Exporter", "AGENT_PATH", fallback="agent.js"))
AGENT = _AGENT_SETTING if _AGENT_SETTING.is_absolute() else ROOT / _AGENT_SETTING
EXPECTED_SHA256 = CONFIG.get(
    "Exporter", "EXPECTED_SHA256",
    fallback="bb765b6fb142cb048717a4a5a3b50de0b795314f2c916807453d8507cd25194d",
).strip().lower()
MAX_CAPTURE = 1024 * 1024 * 1024


class AppError(RuntimeError):
    pass


def configured_target() -> Path:
    return DEFAULT_DZKJ


def validate_target(exe: Path) -> str:
    exe = exe.expanduser().resolve(strict=True)
    if not exe.is_file():
        raise AppError(f"Not a regular file: {exe}")
    with exe.open("rb") as f:
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise AppError("Target does not have a Windows MZ header")
        pe_offset = int.from_bytes(dos[60:64], "little")
        if pe_offset < 64 or pe_offset > 1024 * 1024:
            raise AppError("Malformed PE header offset")
        f.seek(pe_offset)
        header = f.read(128)
        if (len(header) < 84 or header[:4] != b"PE\0\0"
                or int.from_bytes(header[4:6], "little") != 0x8664
                or int.from_bytes(header[24:26], "little") != 0x20b):
            raise AppError("Target is not an AMD64 PE32+ executable")
        if int.from_bytes(header[24 + 56:24 + 60], "little") != 0x818000:
            raise AppError("PE SizeOfImage differs from the supported build")
    sha = hashlib.sha256()
    with exe.open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(part)
    digest = sha.hexdigest()
    if digest != EXPECTED_SHA256:
        raise AppError(f"Unsupported DZKJ executable.\nExpected SHA256: {EXPECTED_SHA256}\nFound SHA256:    {digest}")
    return digest


def process_image(pid: int) -> str | None:
    if sys.platform != "win32":
        return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x1000, 0, pid)
    if not handle:
        return None
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(len(buf))
        if kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value
        return None
    finally:
        kernel.CloseHandle(handle)


def find_process(device, target: Path) -> int | None:
    expected = os.path.normcase(os.path.abspath(target))
    for proc in device.enumerate_processes():
        if proc.name.lower() != "dzkj.exe":
            continue
        actual = process_image(proc.pid)
        if actual and os.path.normcase(os.path.abspath(actual)) == expected:
            return proc.pid
    return None


def unique_name(folder: Path, suggested: str) -> Path:
    name = ntpath.basename(suggested.replace("/", "\\")).strip(" .") or "document.bin"
    forbidden = '<>:"/\\|?*'
    name = "".join("_" if c in forbidden or ord(c) < 32 else c for c in name)
    if not name or name.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))
    }:
        name = "document_" + name
    candidate = folder / name
    i = 2
    while candidate.exists():
        p = Path(name)
        candidate = folder / f"{p.stem}_{i}{p.suffix}"
        i += 1
    return candidate


def pdf_is_complete(path: Path) -> bool:
    # Check PDF markers and its startxref target without loading the whole file.
    try:
        size = path.stat().st_size
        if size < 32:
            return False
        with path.open("rb") as stream:
            if stream.read(5) != b"%PDF-":
                return False
            stream.seek(max(0, size - 4096))
            tail = stream.read(4096)
            eof = tail.rfind(b"%%EOF")
            if eof < 0:
                return False
            xref = tail.rfind(b"startxref", 0, eof)
            if xref < 0:
                return False
            cursor = xref + len(b"startxref")
            while cursor < eof and tail[cursor] in (32, 9, 13, 10):
                cursor += 1
            end = cursor
            while end < eof and 48 <= tail[end] <= 57:
                end += 1
            if end == cursor:
                return False
            offset = int(tail[cursor:end])
            if offset >= size:
                return False
            stream.seek(offset)
            target = stream.read(min(64, size - offset))
            return target.startswith(b"xref") or b"obj" in target
    except (OSError, ValueError):
        return False


def decode_pdf_file(source: Path, destination: Path) -> int:
    # Copy a plain PDF or derive this capture's XOR key from its header, then validate it.
    if pdf_is_complete(source):
        shutil.copyfile(source, destination)
    else:
        with source.open("rb") as src:
            header = src.read(5)
        if len(header) != 5:
            raise AppError("Captured PDF is too short to contain a PDF header")
        key = header[0] ^ ord("%")
        if bytes(byte ^ key for byte in header) != b"%PDF-":
            raise AppError("Captured PDF header does not match the DZKJ payload format")
        table = bytes(byte ^ key for byte in range(256))
        with source.open("rb") as src, destination.open("wb") as dest:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                dest.write(block.translate(table))
        if not pdf_is_complete(destination):
            destination.unlink(missing_ok=True)
            raise AppError("Captured PDF is incomplete or failed the DZKJ XOR decode check")
    if not pdf_is_complete(destination):
        destination.unlink(missing_ok=True)
        raise AppError("Captured PDF failed structural validation")
    return destination.stat().st_size


@dataclass
class Capture:
    id: int
    name: str
    doc_type: int
    tree: bool
    expected: int
    count: int
    password: str | None
    path: Path
    writer: object
    received: int = 0
    chunks: list[Chunk] = field(default_factory=list)
    current_index: int = -1


def new_temp() -> tuple[Path, object]:
    fd, path = tempfile.mkstemp(prefix="xzz_", suffix=".bin")
    return Path(path), os.fdopen(fd, "wb")


class CaptureService:
    def __init__(self, event_sink, output: Path, auto_save: bool, keep_failed: bool = False):
        self.emit = event_sink
        self.output = output
        self.auto_save = auto_save
        self.keep_failed = keep_failed
        self.captures: dict[int, Capture] = {}
        self.lock = threading.Lock()
        self.session = None
        self.script = None
        self.pid = None
        self.ready = threading.Event()
        self.install_error = None
        self.stop_requested = False
        self.worker = None
        self.threads: set[threading.Thread] = set()

    def _message(self, message, data):
        if message.get("type") == "error":
            self.emit("error", f"Frida agent exception: {message.get('stack', message.get('description'))}")
            return
        if message.get("type") != "send":
            return
        p = message.get("payload") or {}
        kind = p.get("kind")
        if kind == "ready":
            self.install_error = None
            self.ready.set()
            self.emit("log", f"Frida hook active in PID {p.get('pid')} at {p.get('base')}")
        elif kind == "init_error":
            self.install_error = str(p.get("message"))
            self.ready.set()
        elif kind == "document_error":
            with self.lock:
                old = self.captures.pop(int(p.get("id", -1)), None)
            if old:
                old.writer.close()
                old.path.unlink(missing_ok=True)
            self.emit("error", f"Capture rejected: {p.get('message')}")
        elif kind in ("document_begin", "document_chunk", "document_end"):
            try:
                self._handle_capture(kind, p, data)
            except Exception as e:
                id_ = int(p.get("id", -1))
                with self.lock:
                    old = self.captures.pop(id_, None)
                if old:
                    old.writer.close()
                    old.path.unlink(missing_ok=True)
                self.emit("error", f"Capture error: {e}")

    def _handle_capture(self, kind, p, data):
        id_ = int(p["id"])
        if kind == "document_begin":
            expected, count = int(p["bytes"]), int(p["count"])
            if not 0 < expected <= MAX_CAPTURE or not 0 < count <= 1048576:
                raise AppError("Invalid document size or chunk count")
            path, writer = new_temp()
            cap = Capture(id_, str(p["name"]), int(p["doc_type"]), bool(p["tree"]),
                          expected, count, p.get("password"), path, writer)
            with self.lock:
                if id_ in self.captures:
                    writer.close()
                    path.unlink(missing_ok=True)
                    raise AppError("Duplicate capture ID")
                self.captures[id_] = cap
            self.emit("log", f"Received {cap.name} (type {cap.doc_type}, {expected:,} bytes)")
            return
        with self.lock:
            cap = self.captures.get(id_)
        if cap is None:
            raise AppError("Document chunk arrived without a begin event")
        if kind == "document_chunk":
            if not isinstance(data, bytes) or not data or len(data) != int(p["size"]):
                raise AppError("Invalid document transfer payload")
            index, position = int(p["index"]), int(p["position"])
            if cap.received + len(data) > cap.expected:
                raise AppError("Document exceeds announced total size")
            if index == cap.current_index + 1:
                cap.current_index = index
                cap.chunks.append(Chunk(cap.received, 0, position))
            elif index != cap.current_index or cap.chunks[-1].position != position:
                raise AppError("Out-of-order document chunk")
            cap.writer.write(data)
            last = cap.chunks[-1]
            cap.chunks[-1] = Chunk(last.offset, last.size + len(data), last.position)
            cap.received += len(data)
            return
        if cap.received != cap.expected or len(cap.chunks) != cap.count:
            raise AppError("Truncated capture or incomplete node sequence")
        cap.writer.close()
        with self.lock:
            self.captures.pop(id_, None)
        worker = threading.Thread(target=self._finish_capture, args=(cap,), daemon=True)
        self.threads.add(worker)
        worker.start()

    def _finish_capture(self, cap: Capture):
        decoded_path = None
        try:
            # Decode and save entirely outside the DZKJ process.
            decoded_path, writer = new_temp()
            writer.close()
            extension = ntpath.splitext(cap.name)[1].lower()
            if cap.doc_type == 2 or extension == ".pdf":
                length = decode_pdf_file(cap.path, decoded_path)
            elif extension == ".pcb":
                if cap.tree and cap.chunks[0].position == 1:
                    length = decode_positioned_file(cap.path, cap.chunks, decoded_path)
                else:
                    length = decode_stream_file(cap.path, decoded_path)
            else:
                shutil.copyfile(cap.path, decoded_path)
                length = decoded_path.stat().st_size
            self.emit("log", f"Prepared {cap.name} ({length:,} bytes)")
            if self.auto_save:
                self.output.mkdir(parents=True, exist_ok=True)
                dest = unique_name(self.output, cap.name)
                with dest.open("xb") as out, decoded_path.open("rb") as source:
                    shutil.copyfileobj(source, out, 1024 * 1024)
                self.emit("saved", str(dest))
                decoded_path.unlink(missing_ok=True)
            else:
                # GUI's dialog MUST run on its own UI thread, not Frida callback.
                self.emit("prompt", (cap.name, decoded_path))
                decoded_path = None
        except Exception as e:
            self.emit("error", f"Could not export {cap.name}: {e}")
            if self.keep_failed or cap.doc_type in (1, 2):
                self.output.mkdir(parents=True, exist_ok=True)
                dest = unique_name(self.output, "FAILED_RAW_" + ntpath.basename(cap.name) + ".bin")
                shutil.copyfile(cap.path, dest)
                self.emit("log", f"Saved raw capture for diagnostics: {dest}")
        finally:
            cap.path.unlink(missing_ok=True)
            if decoded_path:
                decoded_path.unlink(missing_ok=True)
            self.threads.discard(threading.current_thread())

    def _detached(self, reason, crash=None):
        self.emit("error", f"DZKJ session detached: {reason}")

    def start(self, exe: Path, launch: bool = True):
        if self.script is not None and self.session is not None:
            raise AppError("Already attached. Click Detach before starting another session")
        if self.worker and self.worker.is_alive():
            raise AppError("Attachment is already in progress")
        self.stop_requested = False
        self.worker = threading.Thread(target=self._attach_worker, args=(exe, launch), daemon=True)
        self.worker.start()

    def _attach_worker(self, exe: Path, launch: bool):
        try:
            if sys.platform != "win32":
                raise AppError("Live DZKJ hooking requires Windows x64")
            import frida
            exe = exe.expanduser().resolve(strict=True)
            self.emit("log", f"Checking executable: {exe}")
            digest = validate_target(exe)
            self.emit("log", f"Supported SHA256: {digest}")
            device = frida.get_local_device()
            pid = find_process(device, exe)
            if pid is None:
                if not launch:
                    raise AppError("No matching running DZKJ.exe was found")
                self.emit("log", "DZKJ is not running; launching it now")
                new_process = subprocess.Popen([str(exe)], cwd=str(exe.parent))
                pid = new_process.pid
            self.pid = pid
            self.emit("log", f"Attaching to DZKJ PID {pid}")
            self.session = device.attach(pid)
            self.session.on("detached", self._detached)
            source = AGENT.read_text(encoding="utf-8")
            deadline = time.monotonic() + 35
            while not self.stop_requested and time.monotonic() < deadline:
                self.ready.clear()
                self.install_error = None
                self.script = self.session.create_script(source)
                self.script.on("message", self._message)
                self.script.load()
                if not self.ready.wait(5):
                    raise AppError("Frida agent did not report installation status")
                if self.install_error is None:
                    self.emit("log", "Ready. Open a PCB, schematic, or PDF in DZKJ to capture it")
                    return
                err = self.install_error
                self.script.unload()
                self.script = None
                if ("signature" not in err.lower() and "layout" not in err.lower()
                        and "pointer" not in err.lower()):
                    raise AppError(err)
                time.sleep(1)
            raise AppError(self.install_error or "Timed out waiting for DZKJ to unpack the supported code")
        except Exception as e:
            self.emit("error", f"Attach failed: {e}")

    def stop(self):
        self.stop_requested = True
        if self.script:
            try:
                self.script.unload()
            except Exception:
                pass
            self.script = None
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass
            self.session = None
        with self.lock:
            caps = list(self.captures.values())
            self.captures.clear()
        for cap in caps:
            cap.writer.close()
            cap.path.unlink(missing_ok=True)


def run_gui(initial_exe: Path, output: Path):
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, scrolledtext, ttk
    except ImportError as e:
        raise AppError("This Python install does not include Tkinter") from e

    root = tk.Tk()
    root.title("XZZ/DZKJ Exporter by CE")
    root.geometry("830x570")
    root.minsize(680, 450)
    events = queue.Queue()
    exe_var = tk.StringVar(value=str(initial_exe))
    output_var = tk.StringVar(value=str(output))
    autosave_var = tk.BooleanVar(value=False)
    failures_var = tk.BooleanVar(value=False)
    status_var = tk.StringVar(value="Not attached")
    service = CaptureService(lambda kind, value: events.put((kind, value)), output, False)

    def sync_options(*_):
        service.output = Path(output_var.get())
        service.auto_save = autosave_var.get()
        service.keep_failed = failures_var.get()

    autosave_var.trace_add("write", sync_options)
    output_var.trace_add("write", sync_options)
    failures_var.trace_add("write", sync_options)

    frame = ttk.Frame(root, padding=14)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="DZKJ executable").grid(row=0, column=0, sticky="w")
    ttk.Entry(frame, textvariable=exe_var).grid(row=1, column=0, sticky="ew", padx=(0, 8))
    ttk.Button(frame, text="Browse...", command=lambda: exe_var.set(
        filedialog.askopenfilename(title="Select DZKJ.exe", filetypes=[("Executable", "*.exe")]) or exe_var.get()
    )).grid(row=1, column=1)
    ttk.Label(frame, text="Export folder (used by Auto-save)").grid(row=2, column=0, sticky="w", pady=(14, 0))
    ttk.Entry(frame, textvariable=output_var).grid(row=3, column=0, sticky="ew", padx=(0, 8))
    ttk.Button(frame, text="Browse...", command=lambda: output_var.set(
        filedialog.askdirectory(title="Select export folder") or output_var.get()
    )).grid(row=3, column=1)
    ttk.Checkbutton(frame, text="Auto-save captures (no Save As dialog)", variable=autosave_var).grid(row=4, column=0, sticky="w", pady=(12, 0))
    ttk.Checkbutton(frame, text="Keep raw files if PCB decoding fails", variable=failures_var).grid(row=5, column=0, sticky="w")
    controls = ttk.Frame(frame)
    controls.grid(row=6, column=0, columnspan=2, sticky="w", pady=(16, 10))
    ttk.Button(controls, text="Launch / Attach", command=lambda: start()).pack(side="left", padx=(0, 8))
    ttk.Button(controls, text="Attach only", command=lambda: start(False)).pack(side="left", padx=(0, 8))
    ttk.Button(controls, text="Detach", command=lambda: service.stop()).pack(side="left")
    ttk.Label(frame, textvariable=status_var).grid(row=7, column=0, columnspan=2, sticky="w")
    log = scrolledtext.ScrolledText(frame, wrap="word", height=13, state="disabled")
    log.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
    frame.columnconfigure(0, weight=1)
    frame.rowconfigure(8, weight=1)

    def append(text):
        log.configure(state="normal")
        log.insert("end", time.strftime("%H:%M:%S") + "  " + str(text) + "\n")
        log.see("end")
        log.configure(state="disabled")

    def start(launch=True):
        try:
            service.output = Path(output_var.get())
            service.auto_save = autosave_var.get()
            service.keep_failed = failures_var.get()
            service.start(Path(exe_var.get()), launch)
            status_var.set("Attaching...")
        except Exception as e:
            messagebox.showerror("XZZ/DZKJ Exporter by CE", str(e))

    def poll():
        try:
            for _ in range(100):
                kind, value = events.get_nowait()
                if kind == "prompt":
                    name, temp_path = value
                    suggestion = ntpath.basename(name.replace("/", chr(92))) or "document.bin"
                    try:
                        if autosave_var.get():
                            folder = Path(output_var.get())
                            folder.mkdir(parents=True, exist_ok=True)
                            selected = unique_name(folder, name)
                            with temp_path.open("rb") as src, selected.open("xb") as dest:
                                shutil.copyfileobj(src, dest, 1024 * 1024)
                            append(f"Saved: {selected}")
                        else:
                            selected = filedialog.asksaveasfilename(
                                title="Save DZKJ document", initialdir=output_var.get(),
                                initialfile=suggestion, confirmoverwrite=True
                            )
                            if selected:
                                with temp_path.open("rb") as src, open(selected, "wb") as dest:
                                    shutil.copyfileobj(src, dest, 1024 * 1024)
                                append(f"Saved: {selected}")
                            else:
                                append(f"Save cancelled: {suggestion}")
                    except Exception as e:
                        messagebox.showerror("Save failed", str(e))
                    finally:
                        temp_path.unlink(missing_ok=True)
                elif kind == "saved":
                    append(f"Saved: {value}")
                elif kind == "error":
                    append(value)
                    if str(value).startswith("Attach failed") or str(value).startswith("DZKJ session detached"):
                        status_var.set("Not attached")
                else:
                    append(value)
                    if str(value).startswith("Ready."):
                        status_var.set(f"Hook active: PID {service.pid}")
        except queue.Empty:
            pass
        root.after(100, poll)

    def close():
        service.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    root.after(100, poll)
    append("XZZ/DZKJ Exporter by CE is ready. DZKJ is not modified.")
    root.mainloop()


def run_cli(exe: Path, output: Path, attach_only: bool, keep_failed: bool):
    messages = queue.Queue()
    service = CaptureService(lambda k, v: messages.put((k, v)), output, True, keep_failed)
    service.start(exe, not attach_only)
    print("XZZ/DZKJ Exporter by CE: press Ctrl+C to detach")
    try:
        while True:
            try:
                kind, value = messages.get(timeout=0.5)
                print(f"[{kind}] {value}", flush=True)
                if kind == "error" and str(value).startswith("Attach failed"):
                    raise AppError(str(value))
            except queue.Empty:
                pass
    finally:
        service.stop()


def main(argv=None):
    parser = argparse.ArgumentParser(description="XZZ/DZKJ Exporter by CE")
    sub = parser.add_subparsers(dest="command")
    for name in ("gui", "capture", "check"):
        p = sub.add_parser(name)
        p.add_argument("--exe", type=Path, default=configured_target())
        if name != "check":
            p.add_argument("--output", type=Path, default=ROOT / "exports")
        if name == "capture":
            p.add_argument("--attach-only", action="store_true")
            p.add_argument("--keep-failed", action="store_true")
    p = sub.add_parser("repair", help="Decode a wire-format PCB into a new file")
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command in (None, "gui"):
            run_gui(args.exe if args.command else configured_target(), args.output if args.command else ROOT / "exports")
        elif args.command == "check":
            print("Compatible DZKJ executable. SHA256:", validate_target(args.exe))
        elif args.command == "capture":
            run_cli(args.exe, args.output, args.attach_only, args.keep_failed)
        elif args.command == "repair":
            old, new = repair_file(args.input, args.output)
            print(f"Decoded {old:,} bytes into {new:,} PCB bytes: {args.output}")
    except (AppError, OSError, PCBError, ImportError) as e:
        print("ERROR:", e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Detached")
    return 0


if __name__ == "__main__":
    sys.exit(main())
