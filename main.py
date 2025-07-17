from cryptography.fernet import Fernet
import os
from tkinter import *
from tkinter import ttk

# ========== Logic ==========
def encrypt_password():
    password = password_var.get().strip()
    if not password:
        show_output("⚠️ Please enter a password to encrypt.")
        return

    if not os.path.exists('encryption_key.key'):
        key = Fernet.generate_key()
        with open('encryption_key.key', 'wb') as key_file:
            key_file.write(key)
    else:
        with open('encryption_key.key', 'rb') as key_file:
            key = key_file.read()

    fernet = Fernet(key)
    encrypted_pass = fernet.encrypt(password.encode())
    show_output(encrypted_pass.decode())
    return encrypted_pass

def decrypt_password():
    encrypted_text = output_text.get("1.0", END).strip()
    if not encrypted_text:
        show_output("⚠️ Please paste an encrypted password to decrypt.")
        return

    if not os.path.exists('encryption_key.key'):
        show_output("❌ Encryption key not found.")
        return

    try:
        with open('encryption_key.key', 'rb') as key_file:
            key = key_file.read()
        fernet = Fernet(key)
        decrypted_pass = fernet.decrypt(encrypted_text.encode()).decode()
        show_output(decrypted_pass)
    except Exception as e:
        show_output(f"❌ Decryption failed: {str(e)}")

def copy_to_clipboard():
    text = output_text.get("1.0", END).strip()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

def show_output(text):
    output_text.config(state='normal')
    output_text.delete(1.0, END)
    output_text.insert(END, text)
    output_text.config(state='disabled')


# ========== UI ==========
root = Tk()
root.title("🔐 Password Encrypter")
root.geometry("500x400")
root.resizable(False, False)

style = ttk.Style(root)
style.theme_use("clam")

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True)

# ---- Header ----
ttk.Label(frame, text="🔐 Secure Password Encrypter", font=("Segoe UI", 16, "bold")).grid(column=0, row=0, columnspan=2, pady=(0, 10))

# ---- Input ----
ttk.Label(frame, text="Enter password:").grid(column=0, row=1, columnspan=2, sticky='w')
password_var = StringVar()
ttk.Entry(frame, textvariable=password_var, width=50).grid(column=0, row=2, columnspan=2, pady=5)

# ---- Buttons ----
ttk.Button(frame, text="Encrypt Password", command=encrypt_password).grid(column=0, row=3, padx=5, pady=10, sticky="ew")
ttk.Button(frame, text="Decrypt Password", command=decrypt_password).grid(column=1, row=3, padx=5, pady=10, sticky="ew")

# ---- Output ----
ttk.Label(frame, text="Output:").grid(column=0, row=4, columnspan=2, sticky='w')

output_text = Text(frame, height=6, width=58, wrap=WORD, font=("Consolas", 10))
output_text.grid(column=0, row=5, columnspan=2, pady=5)
output_text.config(state='disabled', relief='solid', bd=1)

# ---- Copy Button ----
ttk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard).grid(column=0, row=6, columnspan=2, pady=(10, 0), sticky='ew')

root.mainloop()
