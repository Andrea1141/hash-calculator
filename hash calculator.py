import tkinter, hashlib, subprocess

window = tkinter.Tk()
window.title("Hash Calculator")
window.geometry("1000x500")

option = tkinter.StringVar(value="blake2b")
string = tkinter.StringVar()
auto_update = tkinter.BooleanVar(value=True)
hexdigest = tkinter.StringVar()

title = tkinter.Label(text="HASH CALCULATOR", font=("Arial", 25))
title.pack(pady=25)

label = tkinter.Label(text="Write the string to hash")
label.pack(pady=5)



entry = tkinter.Entry(window, textvariable=string, width=150, justify="center")
entry.pack(pady=5)

def hash(*args):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

hash_button = tkinter.Button(window, text="Hash", command=hash(""))
hash_button.pack(pady=5)


def check_auto_update():
    s = string.trace_add("write", hash)
    opt = option.trace_add("write", hash)
    if auto_update == False:
        string.trace_remove("write", s)
        option.trace_remove("write", opt)

check_auto_update()
check = tkinter.Checkbutton(window, text="Auto Update", variable=auto_update, command=check_auto_update)
check.pack(pady=5)

label = tkinter.Entry(text="", textvariable=hexdigest, width=150, justify="center", state="readonly")
label.pack(pady=5)


algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(window, option, *algorithms)
menu.pack(pady=5)

def copy():
    print(auto_update.get())
    cmd='echo '+hexdigest.get().strip()+'|clip'
    return subprocess.check_call(cmd, shell=True)
    

copy_button = tkinter.Button(window, text="Copy to Clipboard", command=copy)
copy_button.pack(pady=5)

window.mainloop()
