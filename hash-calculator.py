import tkinter, tkinter.messagebox, tkinter.filedialog, tkinter.ttk, hashlib, os, threading, time

window = tkinter.Tk()
window.title("Hash Calculator")
window.geometry("1000x700")
window.config(bg="#333333")
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)

option = tkinter.StringVar(value="blake2b")
string = tkinter.StringVar()
auto_update = tkinter.BooleanVar(value=True)
hexdigest = tkinter.StringVar()
expected_hash = tkinter.StringVar()

title_font = ("Roboto", 25, "bold")
label_font = ("Roboto", 12)
button_font = ("Roboto", 10)
message_font = ("Roboto", 12, "italic")

message_label = None
file_hash_thread = None
file_hash_cancel = None
file_progress_bar = None
file_cancel_button = None
file_progress_label = None
file_hash_start_time = None
file_progress_frame = None
file_buttons_frame = None
history_entries = []
history_listbox = None
history_frame = None

def display_msg():
    if tkinter.messagebox.askyesno(title="Exit", message="Do you want to quit?"):
        window.destroy()
        exit()

window.protocol("WM_DELETE_WINDOW", display_msg)

def auto_hash(*a):
    encoded_string = string.get().encode()
    hasher = hashlib.new(option.get())
    try:
        hasher.update(encoded_string)
        hexdigest.set(hasher.hexdigest())
    except Exception as e:
        show_message("Errore: " + str(e), color="red")

def hash():
    encoded_string = string.get().encode()
    hasher = hashlib.new(option.get())
    try:
        hasher.update(encoded_string)
        hexdigest.set(hasher.hexdigest())
    except Exception as e:
        show_message("Errore: " + str(e), color="red")

def start_file_hash():
    global file_hash_thread, file_hash_cancel, file_progress_bar, file_cancel_button
    _disable_main_buttons(True)
    file_path = tkinter.filedialog.askopenfilename()
    if not file_path:
        return

    if file_hash_thread and file_hash_thread.is_alive():
        show_message("A file hashing job is already running", color="red")
        return

    try:
        file_size = os.path.getsize(file_path)
    except Exception as e:
        show_message("Error accessing file: " + str(e), color="red")
        return

    # Create (or recreate) a centered progress frame that spans both columns
    global file_progress_frame, file_progress_label, file_hash_start_time
    if file_progress_frame:
        try:
            file_progress_frame.destroy()
        except Exception:
            pass
    file_progress_frame = tkinter.Frame(window, bg="#333333")
    file_progress_frame.grid(row=14, column=0, columnspan=2, pady=10)

    file_progress_bar = tkinter.ttk.Progressbar(file_progress_frame, orient="horizontal", length=600, mode="determinate")
    file_progress_bar.pack(side="left", padx=(10, 10))

    if file_cancel_button:
        try:
            file_cancel_button.destroy()
        except Exception:
            pass
    file_cancel_button = tkinter.Button(file_progress_frame, text="Cancel", command=lambda: cancel_file_hash(), font=button_font, bg="#f44336", fg="white")
    file_cancel_button.pack(side="left", padx=(10, 10))

    if file_progress_label:
        try:
            file_progress_label.destroy()
        except Exception:
            pass
    file_progress_label = tkinter.Label(window, text="", font=message_font, bg="#333333")
    file_progress_label.grid(row=15, column=0, columnspan=2, pady=(0, 10))

    file_hash_cancel = threading.Event()

    file_hash_start_time = time.time()
    file_hash_thread = threading.Thread(target=_file_hash_worker, args=(file_path, file_size, file_progress_bar, file_hash_cancel), daemon=True)
    file_hash_thread.start()


def verify():
    expected = expected_hash.get().strip().lower()
    if not expected:
        show_message("Enter expected hash", color="red")
        return

    if string.get().strip():
        try:
            hasher = hashlib.new(option.get())
        except Exception as e:
            show_message("Unsupported algorithm: " + str(e), color="red")
            return
        hasher.update(string.get().encode())
        actual = hasher.hexdigest().lower().strip()
        hexdigest.set(actual)
        if _compare_hashes(expected, actual):
            show_message("PASS — hash is equal", color="green")
            _add_history_entry(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | TEXT | {option.get()} | PASS | 100.00%")
        else:
            idx = _first_mismatch_index(expected, actual)
            snippet_exp = expected[idx:idx+8]
            snippet_act = actual[idx:idx+8]
            show_message(f"FAIL — mismatch at {idx}: expected {snippet_exp} != actual {snippet_act}", color="red")
            mismatches, percent = _hamming_distance(expected, actual)
            _add_history_entry(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | TEXT | {option.get()} | FAIL | {percent:.2f}%")
        return

    start_file_verify(expected)


def start_file_verify(expected):
    global file_hash_thread, file_hash_cancel, file_progress_bar, file_cancel_button, file_progress_frame, file_progress_label, file_hash_start_time
    file_path = tkinter.filedialog.askopenfilename()
    if not file_path:
        return

    if file_hash_thread and file_hash_thread.is_alive():
        show_message("A file hashing job is already running", color="red")
        return

    try:
        file_size = os.path.getsize(file_path)
    except Exception as e:
        show_message("Error accessing file: " + str(e), color="red")
        return


    _disable_main_buttons(True)
    if file_progress_frame:
        try:
            file_progress_frame.destroy()
        except Exception:
            pass
    file_progress_frame = tkinter.Frame(window, bg="#333333")
    file_progress_frame.grid(row=14, column=0, columnspan=2, pady=10)

    file_progress_bar = tkinter.ttk.Progressbar(file_progress_frame, orient="horizontal", length=600, mode="determinate")
    file_progress_bar.pack(side="left", padx=(10, 10))

    if file_cancel_button:
        try:
            file_cancel_button.destroy()
        except Exception:
            pass
    file_cancel_button = tkinter.Button(file_progress_frame, text="Cancel", command=lambda: cancel_file_hash(), font=button_font, bg="#f44336", fg="white")
    file_cancel_button.pack(side="left", padx=(10, 10))

    if file_progress_label:
        try:
            file_progress_label.destroy()
        except Exception:
            pass
    file_progress_label = tkinter.Label(window, text="", font=message_font, bg="#333333")
    file_progress_label.grid(row=15, column=0, columnspan=2, pady=(0, 10))

    file_hash_cancel = threading.Event()

    file_hash_start_time = time.time()
    file_hash_thread = threading.Thread(target=_file_verify_worker, args=(file_path, file_size, file_progress_bar, file_hash_cancel, expected), daemon=True)
    file_hash_thread.start()
    _add_history_entry(f"START file hash: {os.path.basename(file_path)} | algo={option.get()}")


def _file_verify_worker(file_path, file_size, progress_bar, cancel_event, expected):
    try:
        hasher = hashlib.new(option.get())
    except Exception as e:
        window.after(0, lambda: show_message("Unsupported algorithm: " + str(e), color="red"))
        return

    try:
        with open(file_path, "rb") as f:
            chunk_size = 64 * 1024
            read_bytes = 0
            while True:
                if cancel_event.is_set():
                    window.after(0, lambda: show_message("Hashing canceled", color="red"))
                    window.after(0, lambda: _destroy_file_progress_widgets())
                    return
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                read_bytes += len(chunk)
                window.after(0, lambda rb=read_bytes, fs=file_size, pb=progress_bar: update_progress(pb, rb, fs))
                elapsed = max(1e-6, time.time() - file_hash_start_time)
                speed = read_bytes / elapsed  # bytes/sec
                remaining = max(0, file_size - read_bytes)
                eta_seconds = int(remaining / max(1e-6, speed))
                speed_text = f"{speed / (1024*1024):.2f} MB/s"
                eta_text = time.strftime('%H:%M:%S', time.gmtime(eta_seconds))
                window.after(0, lambda stext=speed_text, et=eta_text: _update_progress_label(stext, et))

        digest = hasher.hexdigest().lower().strip()
        window.after(0, lambda d=digest: hexdigest.set(d))
        match = _compare_hashes(expected, digest)
        mismatches, percent = _hamming_distance(expected, digest)
        if match:
            window.after(0, lambda: show_message(f"PASS — hash corrisponde ({percent:.2f}% match)", color="green"))
        else:
            idx = _first_mismatch_index(expected, digest)
            snippet_exp = expected[idx:idx+8]
            snippet_act = digest[idx:idx+8]
            window.after(0, lambda i=idx, se=snippet_exp, sa=snippet_act, p=percent: show_message(f"FAIL — mismatch at {i}: expected {se} != actual {sa} ({p:.2f}% match)", color="red"))
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        entry = f"{ts} | FILE | {os.path.basename(file_path)} | {option.get()} | {'PASS' if match else 'FAIL'} | {percent:.2f}%"
        window.after(0, lambda e=entry: _add_history_entry(e))
    except Exception as e:
        window.after(0, lambda: show_message("Error hashing file: " + str(e), color="red"))
    finally:
        window.after(1000, lambda: _destroy_file_progress_widgets())


def _file_hash_worker(file_path, file_size, progress_bar, cancel_event):
    try:
        hasher = hashlib.new(option.get())
    except Exception as e:
        window.after(0, lambda: show_message("Unsupported algorithm: " + str(e), color="red"))
        return

    try:
        with open(file_path, "rb") as f:
            chunk_size = 64 * 1024
            read_bytes = 0
            while True:
                if cancel_event.is_set():
                    window.after(0, lambda: show_message("Hashing canceled", color="red"))
                    window.after(0, lambda: _destroy_file_progress_widgets())
                    return
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                read_bytes += len(chunk)
                window.after(0, lambda rb=read_bytes, fs=file_size, pb=progress_bar: update_progress(pb, rb, fs))
                elapsed = max(1e-6, time.time() - file_hash_start_time)
                speed = read_bytes / elapsed  # bytes/sec
                remaining = max(0, file_size - read_bytes)
                eta_seconds = int(remaining / max(1e-6, speed))
                # format speed in MB/s and ETA as H:MM:SS
                speed_text = f"{speed / (1024*1024):.2f} MB/s"
                eta_text = time.strftime('%H:%M:%S', time.gmtime(eta_seconds))
                window.after(0, lambda stext=speed_text, et=eta_text: _update_progress_label(stext, et))

            digest = hasher.hexdigest()
            window.after(0, lambda d=digest, fp=file_path: hexdigest.set(d))
            window.after(0, lambda: show_message("Calculated hash for: " + file_path))
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            entry = f"{ts} | FILE-HASH | {os.path.basename(file_path)} | {option.get()} | HASHED"
            window.after(0, lambda e=entry: _add_history_entry(e))
    except Exception as e:
        window.after(0, lambda: show_message("Error hashing file: " + str(e), color="red"))
    finally:
        window.after(1000, lambda: _destroy_file_progress_widgets())


def _update_progress_label(speed_text, eta_text):
    global file_progress_label
    try:
        if file_progress_label:
            file_progress_label.config(text=f"{speed_text} — ETA: {eta_text}", fg="#F5F5F5")
    except Exception:
        pass


def _compare_hashes(expected: str, actual: str) -> bool:
    if expected is None or actual is None:
        return False
    exp = expected.strip().lower()
    act = actual.strip().lower()
    return exp == act


def _first_mismatch_index(expected: str, actual: str) -> int:
    exp = (expected or "").strip().lower()
    act = (actual or "").strip().lower()
    for i, (a, b) in enumerate(zip(exp, act)):
        if a != b:
            return i
    return min(len(exp), len(act))


def _hamming_distance(expected: str, actual: str) -> tuple:
    exp = (expected or "").strip().lower()
    act = (actual or "").strip().lower()
    max_len = max(len(exp), len(act))
    if max_len == 0:
        return 0, 100.0
    mismatches = 0
    for i in range(max_len):
        a = exp[i] if i < len(exp) else None
        b = act[i] if i < len(act) else None
        if a != b:
            mismatches += 1
    matches = max_len - mismatches
    percent = (matches / max_len) * 100.0
    return mismatches, percent


def _disable_main_buttons(disable: bool):
    state = "disabled" if disable else "normal"
    widgets = [
        globals().get('hash_button'),
        globals().get('copy_button'),
        globals().get('file_button'),
        globals().get('save_button'),
        globals().get('verify_button'),
        globals().get('clear_button')
    ]
    for w in widgets:
        try:
            if w:
                w.config(state=state)
        except Exception:
            pass


def _add_history_entry(entry: str, max_entries: int = 50):
    global history_entries, history_listbox, history_frame
    history_entries.insert(0, entry)
    if len(history_entries) > max_entries:
        del history_entries[max_entries:]
    if history_listbox is None:
        return
    try:
        history_listbox.delete(0, tkinter.END)
        for e in history_entries:
            history_listbox.insert(tkinter.END, e)
    except Exception:
        pass


def cancel_file_hash():
    global file_hash_cancel
    if file_hash_cancel:
        file_hash_cancel.set()
        _add_history_entry(f"CANCELED | {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")



def _destroy_file_progress_widgets():
    global file_progress_bar, file_cancel_button, file_progress_label
    try:
        if file_progress_bar:
            file_progress_bar.destroy()
    except Exception:
        pass
    try:
        if file_cancel_button:
            file_cancel_button.destroy()
    except Exception:
        pass
    try:
        if file_progress_label:
            file_progress_label.destroy()
    except Exception:
        pass
    try:
        if file_progress_frame:
            file_progress_frame.destroy()
    except Exception:
        pass
    file_progress_bar = None
    file_cancel_button = None
    file_progress_label = None
    file_progress_frame = None
    _disable_main_buttons(False)

def save_to_file():
    file_path = tkinter.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(f"Hash Calculator Results\nAlgorithm: {option.get()}\nInput: {string.get()}\nHash: {hexdigest.get()}\n")
            show_message("Hash saved to " + file_path)
        except Exception as e:
            show_message("Error saving file: " + str(e), color="red")

def check_auto_update():
    global s, opt
    try:
        s
    except NameError:
        s = None
    try:
        opt
    except NameError:
        opt = None

    if auto_update.get():
        if s is None:
            s = string.trace_add("write", auto_hash)
        if opt is None:
            opt = option.trace_add("write", auto_hash)
    else:
        if s is not None:
            try:
                string.trace_remove("write", s)
            except Exception:
                pass
            s = None
        if opt is not None:
            try:
                option.trace_remove("write", opt)
            except Exception:
                pass
            opt = None

def copy():
    try:
        window.clipboard_clear()
        window.clipboard_append(hexdigest.get().strip())
        show_message("Text copied to clipboard!")
    except Exception as e:
        show_message("Error copying to clipboard: " + str(e), color="red")

def clear_field():
    string.set("")
    hexdigest.set("")
    show_message("Text cleared!")

def show_message(msg, color="green"):
    global message_label
    if message_label:
        message_label.destroy()
    message_label = tkinter.Label(window, text=msg, fg=color, bg="#333333", font=message_font)
    message_label.grid(row=14, column=0, columnspan=2, pady=5)
    window.after(3000, lambda: message_label.destroy())

def update_progress(progress_bar, current, total):
    percentage = (current / total) * 100
    progress_bar["value"] = percentage
    window.update_idletasks()

title = tkinter.Label(text="HASH CALCULATOR", font=title_font, bg="#333333", fg="#F5F5F5")
title.grid(row=0, column=0, columnspan=2, pady=20)

label = tkinter.Label(text="Write the string to hash", font=label_font, bg="#333333", fg="#F5F5F5")
label.grid(row=1, column=0, columnspan=2, pady=10)

entry = tkinter.Entry(window, textvariable=string, width=100, justify="center", font=("Roboto", 12), bg="#4e4e4e", fg="#F5F5F5")
entry.grid(row=2, column=0, columnspan=2, pady=10)

clear_button = tkinter.Button(window, text="Clear", command=clear_field, font=button_font, bg="#f4b084", fg="#F5F5F5")
clear_button.grid(row=3, column=0, columnspan=2, pady=10)

hash_button = tkinter.Button(window, text="Hash", command=hash, font=button_font, bg="#4caf50", fg="#F5F5F5")
hash_button.grid(row=4, column=0, padx=50, pady=10, sticky="e")

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update, font=label_font, bg="#333333")
check.grid(row=4, column=1, padx=10, pady=10, sticky="w")

label = tkinter.Message(text="", textvariable=hexdigest, width=900, justify="center", font=("Arial", 12), fg="#F5F5F5", bg="#333333")
label.grid(row=5, column=0, columnspan=2, pady=10)

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.config(font=label_font, bg="#333333", fg="#F5F5F5")
menu.grid(row=6, column=0, columnspan=2, pady=10)

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy, font=button_font, bg="#2196f3", fg="#F5F5F5")
copy_button.grid(row=7, column=0, columnspan=2, pady=10)

verify_frame = tkinter.Frame(window, bg="#333333")
verify_frame.grid(row=8, column=0, columnspan=2, pady=6)

verify_label = tkinter.Label(verify_frame, text="Expected hash:", font=label_font, bg="#333333", fg="#F5F5F5")
verify_label.pack(side="left", padx=(0,8))

verify_entry = tkinter.Entry(verify_frame, textvariable=expected_hash, width=74, justify="center", font=("Roboto", 11), bg="#4e4e4e", fg="#F5F5F5")
verify_entry.pack(side="left", padx=(0,8))

verify_button = tkinter.Button(verify_frame, text="Verify", command=verify, font=button_font, bg="#ff9800", fg="#333333")
verify_button.pack(side="left", padx=(0,8))

file_button = tkinter.Button(window, text="Hash File", command=start_file_hash, font=button_font, bg="#2196f3", fg="#F5F5F5")
file_button.grid(row=10, column=0, padx=50, pady=10, sticky="e")

save_button = tkinter.Button(window, text="Save to File", command=save_to_file, font=button_font, bg="#2196f3", fg="#F5F5F5")
save_button.grid(row=10, column=1, padx=10, pady=10, sticky="w")


history_frame = tkinter.Frame(window, bg="#333333")
history_frame.grid(row=13, column=0, columnspan=2, pady=(10,0), padx=20, sticky="ew")
history_label = tkinter.Label(history_frame, text="History (latest first):", font=label_font, bg="#333333", fg="#F5F5F5")
history_label.pack(anchor="w")
history_listbox = tkinter.Listbox(history_frame, height=6, bg="#4e4e4e", fg="#F5F5F5", width=120)
history_listbox.pack(fill="both", expand=True, pady=(5,0))

window.mainloop()

