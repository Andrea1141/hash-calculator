import tkinter, hashlib

root = tkinter.Tk()
root.title("Hash Program")

label = tkinter.Label(text="Write the string to hash")
label.pack()

string = tkinter.StringVar()
option = tkinter.StringVar()
option.set("sha256")

entry = tkinter.Entry(root, textvariable=string)
entry.pack()

hexdigest = tkinter.StringVar()
label = tkinter.Entry(text="", textvariable=hexdigest, width=70, justify="center", state="readonly")
label.pack()

def callback(_, __, ___):
    encoded_string = string.get().encode()
    command = "hashlib." + option.get() + "(encoded_string)"
    result = eval(command)
    hexdigest.set(result.hexdigest())
    
string.trace_add("write", callback)
option.trace_add("write", callback)

menu = tkinter.OptionMenu(root, option, "sha256", "md5", "sha1")
menu.pack()

root.mainloop()
