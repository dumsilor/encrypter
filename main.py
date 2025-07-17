from cryptography.fernet import Fernet
import os
from tkinter import *
from tkinter import ttk

fernet = None

def encrypt_password():
    password = password_var.get()
    if not os.path.exists('encryption_key.key'):
        key = Fernet.generate_key()
        fernet = Fernet(key)
        with open('encryption_key.key', 'wb') as key_file:
            key_file.write(key)
    else:
        with open('encryption_key.key', 'rb') as key_file:
            key = key_file.read()
            fernet = Fernet(key)

    txt_pass = password

    encrypted_pass = fernet.encrypt(txt_pass.encode())

    # with open ('encrypted_passwords.txt', 'ab') as pass_file:
    #     pass_file.write(encrypted_pass+ b'\n')
    # output_var.set(encrypted_pass.decode())

    show_output(encrypted_pass.decode())
    return encrypted_pass

def decrypt_password():
    decrypted_pass_list = []
    password = password_var.get()
    if not os.path.exists('encryption_key.key'):
        print("Encryption key not found. Please encrypt a password first.")
        return

    with open('encryption_key.key', 'rb') as key_file:
        key = key_file.read()
        fernet = Fernet(key)

    with open('encrypted_passwords.txt', 'rb') as pass_file:
        for line in pass_file:
            decrypted_pass = fernet.decrypt(password)
            # decrypted_pass_list.append(decrypted_pass)
    result = "\n".join(decrypted_pass_list)
    # output_var.set(decrypted_pass)    
    show_output(decrypted_pass)
    return decrypted_pass_list

def copy_to_clipboard():
    root.clipboard_clear()
    copied_text = output_text.get(1.0, END).strip()
    root.clipboard_append(copied_text)
    root.update()  # Keeps the clipboard content available after the window is closed


root = Tk()
frame = ttk.Frame(root, padding=10)
frame.grid()
ttk.Label(frame, text="Password Encrypter").grid(column=0, row=0, columnspan=2)
ttk.Button(frame, text="Encrypt Password", command=encrypt_password).grid(column=0, row=1)
ttk.Button(frame, text="Decrypt Password", command=decrypt_password).grid(column=1 , row=1)

password_var = StringVar()
ttk.Entry(frame, textvariable=password_var, width=30).grid(column=0, row=2, columnspan=2)

# output_label = ttk.Label(frame, text="", wraplength=250, state='readonly')
# output_label.grid(column=0, row=4, columnspan=2)

# output_var = StringVar()
# output_entry = ttk.Entry(frame, textvariable=output_var, width=60, state='readonly')
# output_entry.grid(column=0, row=4, columnspan=2)

output_text = Text(frame, height=5, width=60)
output_text.grid(column=0, row=4, columnspan=2)

def show_output(text):
    output_text.config(state='normal')
    output_text.delete(1.0, END)
    output_text.insert(END, text)
    output_text.config(state='disabled')

ttk.Button(frame, text="Copy", command=copy_to_clipboard).grid(column=0, row=5, columnspan=2)

root.mainloop()


# print(encrypt_password())
# print(decrypt_password())
