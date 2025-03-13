import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte key using PBKDF2 with SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """Encrypts a file using AES-256 CBC mode."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    encrypted_data = salt + iv + ciphertext
    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_data)
    
    messagebox.showinfo("Success", "File encrypted successfully!")

def decrypt_file(file_path, password):
    """Decrypts an AES-256 CBC encrypted file."""
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    
    decrypted_file_path = file_path.replace(".enc", "_decrypted")
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)
    
    messagebox.showinfo("Success", "File decrypted successfully!")

def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        encrypt_file(file_path, password)

def select_file_decrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        decrypt_file(file_path, password)

# GUI Setup
root = tk.Tk()
root.title("AES-256 File Encryptor")

tk.Label(root, text="Enter Password:").pack()
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

tk.Button(root, text="Encrypt File", command=select_file_encrypt).pack()
tk.Button(root, text="Decrypt File", command=select_file_decrypt).pack()

root.mainloop()
