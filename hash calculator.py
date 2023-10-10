import tkinter, hashlib

root = tkinter.Tk()
root.title("Hash Calculator")

label = tkinter.Label(text="Write the string to hash")
label.pack()

option = tkinter.StringVar()
option.set("sha224")
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

algorithms = ["sha224", "sha1", "blake2s", "sha3_384", "sha256", "blake2b", "sha384", "sha3_256", "sha3_512", "md5", "sha512", "sha3_224"]
menu = tkinter.OptionMenu(root, option, *algorithms)
menu.pack()
callback()

root.mainloop()
