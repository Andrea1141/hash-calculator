import tkinter, tkinter.messagebox, tkinter.filedialog, hashlib, subprocess

window = tkinter.Tk()
window.title("Hash Calculator")
window.geometry("1000x500")
window.config(bg="#f0f0f0")
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)

option = tkinter.StringVar(value="blake2b")
string = tkinter.StringVar()
auto_update = tkinter.BooleanVar(value=True)
hexdigest = tkinter.StringVar()

title_font = ("Roboto", 25, "bold")
label_font = ("Roboto", 12)
button_font = ("Roboto", 10)
message_font = ("Roboto", 10, "italic")

message_label = None

def display_msg():
    if tkinter.messagebox.askyesno(title="Exit", message="Do you want to quit?"):
        window.destroy()
        exit()

window.protocol("WM_DELETE_WINDOW", display_msg)

def auto_hash(*a):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    try:
        result = eval(command)
        hexdigest.set(result.hexdigest())
    except Exception as e:
        show_message("Errore: " + str(e), color="red")

def hash():
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    try:
        result = eval(command)
        hexdigest.set(result.hexdigest())
    except Exception as e:
        show_message("Errore: " + str(e), color="red")

def hash_file():
    file_path = tkinter.filedialog.askopenfilename()
    if not file_path:
        return
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            result = eval("hashlib." + option.get() + "(file_content)")
            hexdigest.set(result.hexdigest())
            show_message("Calculated hash for the file: " + file_path)
    except Exception as e:
        show_message("Error: " + str(e), color="red")

def check_auto_update():
    if string.trace_info() == []:
        global s 
        s = string.trace_add("write", auto_hash)
        global opt 
        opt = option.trace_add("write", auto_hash)
    if not auto_update.get():
        string.trace_remove("write", s)
        option.trace_remove("write", opt)
    else:
        hash()

def copy():
    cmd = 'echo '+ hexdigest.get().strip() +'|clip'
    subprocess.check_call(cmd, shell=True)
    show_message("Text copied to clipboard!")

def clear_field():
    string.set("")
    hexdigest.set("")
    show_message("Text cleared!")

def show_message(msg, color="green"):
    global message_label
    if message_label:
        message_label.destroy()
    message_label = tkinter.Label(window, text=msg, fg=color, bg="#f0f0f0", font=message_font)
    message_label.grid(row=10, column=0, columnspan=2, pady=5)
    window.after(3000, lambda: message_label.destroy())

title = tkinter.Label(text="HASH CALCULATOR", font=title_font, bg="#f0f0f0")
title.grid(row=0, column=0, columnspan=2, pady=20)

label = tkinter.Label(text="Write the string to hash", font=label_font, bg="#f0f0f0")
label.grid(row=1, column=0, columnspan=2, pady=10)

entry = tkinter.Entry(window, textvariable=string, width=150, justify="center", font={"Roboto", 12})
entry.grid(row=2, column=0, columnspan=2, pady=10)

clear_button = tkinter.Button(window, text="Clear", command=clear_field, font=button_font, bg="#f4b084")
clear_button.grid(row=3, column=0, columnspan=2, pady=10)

hash_button = tkinter.Button(window, text="Hash", command=hash, font=button_font, bg="#4caf50", fg="white")
hash_button.grid(row=5, column=0, padx=50, pady=10, sticky="e")

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update, font=label_font, bg="#f0f0f0")
check.grid(row=5, column=1, padx=10, pady=10, sticky="w")

label = tkinter.Entry(text="", textvariable=hexdigest, width=150, justify="center", state="readonly", font=("Arial", 12))
label.grid(row=6, column=0, columnspan=2, pady=10)

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.config(font=label_font, bg="#f0f0f0")
menu.grid(row=7, column=0, columnspan=2, pady=10)

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy, font=button_font, bg="#2196f3", fg="white")
copy_button.grid(row=8, column=0, columnspan=2, pady=10)

file_button = tkinter.Button(window, text="Hash File", command=hash_file, font=button_font, bg="#2196f3", fg="white")
file_button.grid(row=9, column=0, columnspan=2, pady=10)

window.mainloop()

