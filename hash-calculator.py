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
    file_progress_frame.grid(row=11, column=0, columnspan=2, pady=10)

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
    file_progress_label.grid(row=12, column=0, columnspan=2, pady=(0, 10))

    file_hash_cancel = threading.Event()

    file_hash_start_time = time.time()
    file_hash_thread = threading.Thread(target=_file_hash_worker, args=(file_path, file_size, file_progress_bar, file_hash_cancel), daemon=True)
    file_hash_thread.start()


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


def cancel_file_hash():
    global file_hash_cancel
    if file_hash_cancel:
        file_hash_cancel.set()



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
hash_button.grid(row=5, column=0, padx=50, pady=10, sticky="e")

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update, font=label_font, bg="#333333")
check.grid(row=5, column=1, padx=10, pady=10, sticky="w")

label = tkinter.Message(text="", textvariable=hexdigest, width=900, justify="center", font=("Arial", 12), fg="#F5F5F5", bg="#333333")
label.grid(row=6, column=0, columnspan=2, pady=10)

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.config(font=label_font, bg="#333333", fg="#F5F5F5")
menu.grid(row=7, column=0, columnspan=2, pady=10)

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy, font=button_font, bg="#2196f3", fg="#F5F5F5")
copy_button.grid(row=8, column=0, columnspan=2, pady=10)

file_button = tkinter.Button(window, text="Hash File", command=start_file_hash, font=button_font, bg="#2196f3", fg="#F5F5F5")
file_button.grid(row=9, column=0, padx=50, pady=10, sticky="e")

save_button = tkinter.Button(window, text="Save to File", command=save_to_file, font=button_font, bg="#2196f3", fg="#F5F5F5")
save_button.grid(row=9, column=1, padx=10, pady=10, sticky="w")

window.mainloop()

