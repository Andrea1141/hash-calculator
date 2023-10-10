import tkinter, hashlib, subprocess

root = tkinter.Tk()
root.title("Hash Calculator")

label = tkinter.Label(text="Write the string to hash")
label.pack()

option = tkinter.StringVar()
option.set("blake2b")
string = tkinter.StringVar()

entry = tkinter.Entry(root, textvariable=string, width=150, justify="center")
entry.pack()

hexdigest = tkinter.StringVar()
label = tkinter.Entry(text="", textvariable=hexdigest, width=150, justify="center", state="readonly")
label.pack()

def callback(*args):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())

string.trace_add("write", callback)
option.trace_add("write", callback)

algorithms = ['blake2b', 'blake2s', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'sha512']
menu = tkinter.OptionMenu(root, option, *algorithms)
menu.pack()
callback()

def copy():
    cmd='echo '+hexdigest.get().strip()+'|clip'
    return subprocess.check_call(cmd, shell=True)

copy_button = tkinter.Button(root, text="Copy to Clipboard", command=copy)
copy_button.pack()

root.mainloop()
