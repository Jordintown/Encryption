import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import time
import os

# Function to convert bytes to hex
def bytes_to_hex(byte_array):
    return ''.join(f'{byte:02x}' for byte in byte_array)

# Function to convert hex to bytes
def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

# Function to encrypt file
def encrypt_file(file_path, progress, time_remaining):
    start_time = time.time()
    
    with open(file_path, 'rb') as file:
        file_bytes = file.read()
    
    hex_data = bytes_to_hex(file_bytes)
    
    # Encrypted title: converting original filename to hex
    encrypted_title = bytes_to_hex(os.path.basename(file_path).encode('utf-8'))
    
    encrypted_file_path = os.path.join(os.path.dirname(file_path), f'{encrypted_title}.dmecyp')
    
    with open(encrypted_file_path, 'w') as encrypted_file:
        encrypted_file.write(hex_data)
    
    elapsed_time = time.time() - start_time
    progress['value'] = 100
    time_remaining.set(f"Time remaining: {elapsed_time:.2f} seconds")
    messagebox.showinfo("Done", "File encrypted successfully!")

# Function to decrypt file
def decrypt_file(file_path, progress, time_remaining):
    start_time = time.time()
    
    with open(file_path, 'r') as file:
        hex_data = file.read()
    
    file_bytes = hex_to_bytes(hex_data)
    
    # Decrypted title: converting hex to original filename
    decrypted_title = hex_to_bytes(os.path.basename(file_path).split('.')[0]).decode('utf-8')
    
    decrypted_file_path = os.path.join(os.path.dirname(file_path), decrypted_title)
    
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(file_bytes)
    
    elapsed_time = time.time() - start_time
    progress['value'] = 100
    time_remaining.set(f"Time remaining: {elapsed_time:.2f} seconds")
    messagebox.showinfo("Done", "File decrypted successfully!")

def select_file(operation, progress, time_remaining):
    file_path = filedialog.askopenfilename()
    if file_path:
        progress['value'] = 0
        time_remaining.set("Time remaining: calculating...")
        if operation == 'encrypt':
            encrypt_file(file_path, progress, time_remaining)
        elif operation == 'decrypt':
            decrypt_file(file_path, progress, time_remaining)

# Create the main window
root = tk.Tk()
root.title("File Encrypter/Decrypter")

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

# Run the application
root.mainloop()
