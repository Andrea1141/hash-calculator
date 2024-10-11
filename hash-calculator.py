import tkinter, tkinter.messagebox, tkinter.filedialog, hashlib, subprocess

window = tkinter.Tk()
window.title("Hash Calculator")
window.geometry("1000x500")
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)

option = tkinter.StringVar(value="blake2b")
string = tkinter.StringVar()
auto_update = tkinter.BooleanVar(value=True)
hexdigest = tkinter.StringVar()

title_font = ("Century", 25, "bold")

message_label = None

def display_msg():
    if tkinter.messagebox.askyesno(title="Exit", message="Do you want to quit?"):
        window.destroy()
        exit()

window.protocol("WM_DELETE_WINDOW", display_msg)

def auto_hash(*a):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

def hash():
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

def hash_file():
    file_path = tkinter.filedialog.askopenfilename()
    if not file_path:
        return
    try:
        with open(file_path, "rb") as file:
            file_content = file.read()
            result = eval("hashlib." + option.get() + "(file_content)")
            hexdigest.set(result.hexdigest())
            show_message("Hash calcolato per il file: " + file_path)
    except Exception as e:
        show_message("Errore: " + str(e))
            

def check_auto_update():
    if string.trace_info() == []:
        global s 
        s = string.trace_add("write", auto_hash)
        global opt 
        opt = option.trace_add("write", auto_hash)
    if auto_update.get() == False:
        string.trace_remove("write", s)
        option.trace_remove("write", opt)
    else:
        hash()

def copy():
    cmd='echo '+hexdigest.get().strip()+'|clip'
    subprocess.check_call(cmd, shell=True)
    show_message("Text copied to clipboard!")

def clear_field():
    string.set("")
    option.set("")
    show_message("Text cleared!")

def show_message(msg):
    global message_label
    if message_label:
        message_label.destroy()
    message_label = tkinter.Label(window, text=msg, fg="green")
    message_label.grid(row=10, column=0, columnspan=2, pady=5, sticky="n")
    window.after(2000, lambda: message_label.destroy())


title = tkinter.Label(text="HASH CALCULATOR", font=title_font)
title.grid(row=0, column=0, columnspan=2, pady=25, sticky="n")

label = tkinter.Label(text="Write the string to hash")
label.grid(row=1, column=0, columnspan=2, pady=5, sticky="n")

entry = tkinter.Entry(window, textvariable=string, width=150, justify="center")
entry.grid(row=2, column=0, columnspan=2, pady=5, sticky="n")

clear_button = tkinter.Button(window, text="Clear", command=clear_field)
clear_button.grid(row=3, column=0, columnspan=2, pady=5, sticky="n")

hash_button = tkinter.Button(window, text="Hash", command=hash)
hash_button.grid(row=5, column=0, padx=50, pady=5, sticky="e")

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update)
check.grid(row=5, column=1, padx=10, pady=5, sticky="w")

label = tkinter.Entry(text="", textvariable=hexdigest, width=150, justify="center", state="readonly")
label.grid(row=6, column=0, columnspan=2, pady=5, sticky="n")

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.grid(row=7, column=0, columnspan=2, pady=5, sticky="n")

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy)
copy_button.grid(row=8, column=0, columnspan=2, pady=5, sticky="n")

file_button = tkinter.Button(window, text="Hash File", command=hash_file)
file_button.grid(row=9, column=0, columnspan=2, pady=5, sticky="n")

window.mainloop()
=======
import tkinter, tkinter.messagebox, hashlib, subprocess

window = tkinter.Tk()
window.title("Hash Calculator")
window.geometry("1000x500")
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)

option = tkinter.StringVar(value="blake2b")
string = tkinter.StringVar()
auto_update = tkinter.BooleanVar(value=True)
hexdigest = tkinter.StringVar()

title_font = ("Century", 25, "bold")

message_label = None

def display_msg():
    if tkinter.messagebox.askyesno(title="Exit", message="Do you want to quit?"):
        window.destroy()
        exit()

window.protocol("WM_DELETE_WINDOW", display_msg)

def auto_hash(*a):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

def hash():
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

def check_auto_update():
    if string.trace_info() == []:
        global s 
        s = string.trace_add("write", auto_hash)
        global opt 
        opt = option.trace_add("write", auto_hash)
    if auto_update.get() == False:
        string.trace_remove("write", s)
        option.trace_remove("write", opt)
    else:
        hash()

def copy():
    cmd='echo '+hexdigest.get().strip()+'|clip'
    subprocess.check_call(cmd, shell=True)
    show_message("Text copied to clipboard!")

def clear_field():
    string.set("")
    option.set("")
    show_message("Text cleared!")

def show_message(msg):
    global message_label
    if message_label:
        message_label.destroy()
    message_label = tkinter.Label(window, text=msg, fg="green")
    message_label.grid(row=9, column=0, columnspan=2, pady=5, sticky="n")
    window.after(2000, lambda: message_label.destroy())


title = tkinter.Label(text="HASH CALCULATOR", font=title_font)
title.grid(row=0, column=0, columnspan=2, pady=25, sticky="n")

label = tkinter.Label(text="Write the string to hash")
label.grid(row=1, column=0, columnspan=2, pady=5, sticky="n")

entry = tkinter.Entry(window, textvariable=string, width=150, justify="center")
entry.grid(row=2, column=0, columnspan=2, pady=5, sticky="n")

clear_button = tkinter.Button(window, text="Clear", command=clear_field)
clear_button.grid(row=3, column=0, columnspan=2, pady=5, sticky="n")

hash_button = tkinter.Button(window, text="Hash", command=hash)
hash_button.grid(row=5, column=0, padx=50, pady=5, sticky="e")

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update)
check.grid(row=5, column=1, padx=10, pady=5, sticky="w")

label = tkinter.Entry(text="", textvariable=hexdigest, width=150, justify="center", state="readonly")
label.grid(row=6, column=0, columnspan=2, pady=5, sticky="n")

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.grid(row=7, column=0, columnspan=2, pady=5, sticky="n")

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy)
copy_button.grid(row=8, column=0, columnspan=2, pady=5, sticky="n")

window.mainloop()