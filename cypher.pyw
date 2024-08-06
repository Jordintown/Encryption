import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
import threading
import time
import sys

# Function to generate key from password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Function to encrypt data with AES
def aes_encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

# Function to decrypt data with AES
def aes_decrypt(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return data

# Function to convert bytes to hex
def bytes_to_hex(byte_array):
    return ''.join(f'{byte:02x}' for byte in byte_array)

# Function to convert hex to bytes
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# Function to format time in hours, minutes, and seconds
def format_time(seconds):
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

# Function to encrypt file
def encrypt_file(file_path, password, progress, time_remaining):
    chunk_size = 1024 * 1024  # 1MB
    start_time = time.time()

    file_size = os.path.getsize(file_path)
    processed_size = 0

    # Generate encryption key
    SALT = os.urandom(16)
    key = generate_key(password, SALT)

    with open(file_path, 'rb') as file:
        encrypted_title = bytes_to_hex(aes_encrypt(os.path.basename(file_path).encode('utf-8'), key))
        encrypted_file_path = os.path.join(os.path.dirname(file_path), f'{encrypted_title}.dmecyp')
        
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(bytes_to_hex(SALT).encode('utf-8'))  # Store SALT in file
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                encrypted_data = aes_encrypt(chunk, key)
                hex_data = bytes_to_hex(encrypted_data)
                encrypted_file.write(hex_data.encode('utf-8'))
                
                processed_size += len(chunk)
                progress['value'] = (processed_size / file_size) * 100
                root.update_idletasks()
                
                elapsed_time = time.time() - start_time
                processed_fraction = processed_size / file_size if file_size > 0 else 0
                remaining_time = (elapsed_time / processed_fraction - elapsed_time) if processed_fraction > 0 else 0
                time_remaining.set(f"Time remaining: {format_time(remaining_time)}")
    
    messagebox.showinfo("Done", "File encrypted successfully!")

# Function to decrypt file
def decrypt_file(file_path, password, progress, time_remaining):
    chunk_size = 2 * 1024 * 1024  # 2MB because each byte is represented by 2 hex characters
    start_time = time.time()

    file_size = os.path.getsize(file_path)
    processed_size = 0

    try:
        with open(file_path, 'r') as file:
            SALT = hex_to_bytes(file.read(32))  # Read the first 32 hex chars (16 bytes) as SALT
            key = generate_key(password, SALT)
            encrypted_title = os.path.basename(file_path).split('.')[0]
            decrypted_title = aes_decrypt(hex_to_bytes(encrypted_title), key).decode('utf-8')
            decrypted_file_path = os.path.join(os.path.dirname(file_path), decrypted_title)
            
            with open(decrypted_file_path, 'wb') as decrypted_file:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    encrypted_data = hex_to_bytes(chunk)
                    decrypted_data = aes_decrypt(encrypted_data, key)
                    decrypted_file.write(decrypted_data)
                    
                    processed_size += len(chunk) // 2  # Each byte is represented by 2 hex characters
                    progress['value'] = (processed_size / file_size) * 100
                    root.update_idletasks()
                    
                    elapsed_time = time.time() - start_time
                    processed_fraction = processed_size / file_size if file_size > 0 else 0
                    remaining_time = (elapsed_time / processed_fraction - elapsed_time) if processed_fraction > 0 else 0
                    time_remaining.set(f"Time remaining: {format_time(remaining_time)}")

        messagebox.showinfo("Done", "File decrypted successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def select_file(operation, progress, time_remaining):
    file_path = filedialog.askopenfilename()
    if file_path:
        password = simpledialog.askstring("Password", "Enter the password:", show='*')
        if not password:
            messagebox.showwarning("Canceled", f"{operation.capitalize()} was canceled by the user.")
            return
        progress['value'] = 0
        time_remaining.set("Time remaining: calculating...")
        thread = threading.Thread(target=process_file, args=(file_path, password, operation, progress, time_remaining))
        thread.start()

def process_file(file_path, password, operation, progress, time_remaining):
    if operation == 'encrypt':
        encrypt_file(file_path, password, progress, time_remaining)
    elif operation == 'decrypt':
        decrypt_file(file_path, password, progress, time_remaining)

def process_direct_file(file_path):
    if file_path.endswith(".dmecyp"):
        password = simpledialog.askstring("Password", "Enter the password to decrypt:", show='*')
        if not password:
            messagebox.showwarning("Canceled", "Decryption was canceled by the user.")
            return
        progress['value'] = 0
        time_remaining.set("Time remaining: calculating...")
        thread = threading.Thread(target=decrypt_file, args=(file_path, password, progress, time_remaining))
        thread.start()
    else:
        password = simpledialog.askstring("Password", "Enter a password to encrypt:", show='*')
        if not password:
            messagebox.showwarning("Canceled", "Encryption was canceled by the user.")
            return
        progress['value'] = 0
        time_remaining.set("Time remaining: calculating...")
        thread = threading.Thread(target=encrypt_file, args=(file_path, password, progress, time_remaining))
        thread.start()

# Create the main window
root = tk.Tk()
root.title("Secure File Encrypter/Decrypter")

# Create widgets
select_encrypt_button = tk.Button(root, text="Select File to Encrypt", command=lambda: select_file('encrypt', progress, time_remaining))
select_decrypt_button = tk.Button(root, text="Select File to Decrypt", command=lambda: select_file('decrypt', progress, time_remaining))
progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
time_remaining = tk.StringVar()
time_remaining_label = tk.Label(root, textvariable=time_remaining)

# Layout
select_encrypt_button.pack(pady=10)
select_decrypt_button.pack(pady=10)
progress.pack(pady=10)
time_remaining_label.pack(pady=10)

# Check for direct file processing
if len(sys.argv) > 1:
    file_path = sys.argv[1]
    process_direct_file(file_path)

# Run the application
root.mainloop()
