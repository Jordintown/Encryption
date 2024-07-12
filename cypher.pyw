import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import time
import os
import threading

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
def encrypt_file(file_path, progress, time_remaining):
    chunk_size = 1024 * 1024  # 1MB
    start_time = time.time()
    
    file_size = os.path.getsize(file_path)
    processed_size = 0
    total_time = 0

    with open(file_path, 'rb') as file:
        encrypted_title = bytes_to_hex(os.path.basename(file_path).encode('utf-8'))
        encrypted_file_path = os.path.join(os.path.dirname(file_path), f'{encrypted_title}.dmecyp')
        
        with open(encrypted_file_path, 'w') as encrypted_file:
            while chunk := file.read(chunk_size):
                chunk_start_time = time.time()
                
                hex_data = bytes_to_hex(chunk)
                encrypted_file.write(hex_data)
                
                processed_size += len(chunk)
                progress['value'] = (processed_size / file_size) * 100
                root.update_idletasks()
                
                chunk_end_time = time.time()
                total_time += (chunk_end_time - chunk_start_time)
                average_speed = processed_size / total_time
                remaining_size = file_size - processed_size
                remaining_time = remaining_size / average_speed
                formatted_time = format_time(remaining_time)
                time_remaining.set(f"Time remaining: {formatted_time}")
    
    elapsed_time = time.time() - start_time
    formatted_elapsed_time = format_time(elapsed_time)
    time_remaining.set(f"Time elapsed: {formatted_elapsed_time}")
    messagebox.showinfo("Done", "File encrypted successfully!")

# Function to decrypt file
def decrypt_file(file_path, progress, time_remaining):
    chunk_size = 2 * 1024 * 1024  # 2MB because each byte is represented by 2 hex characters
    start_time = time.time()
    
    file_size = os.path.getsize(file_path)
    processed_size = 0
    total_time = 0

    with open(file_path, 'r') as file:
        encrypted_title = os.path.basename(file_path).split('.')[0]
        decrypted_title = hex_to_bytes(encrypted_title).decode('utf-8')
        decrypted_file_path = os.path.join(os.path.dirname(file_path), decrypted_title)
        
        with open(decrypted_file_path, 'wb') as decrypted_file:
            while chunk := file.read(chunk_size):
                chunk_start_time = time.time()
                
                file_bytes = hex_to_bytes(chunk)
                decrypted_file.write(file_bytes)
                
                processed_size += len(chunk)
                progress['value'] = (processed_size / file_size) * 100
                root.update_idletasks()
                
                chunk_end_time = time.time()
                total_time += (chunk_end_time - chunk_start_time)
                average_speed = processed_size / total_time
                remaining_size = file_size - processed_size
                remaining_time = remaining_size / average_speed
                formatted_time = format_time(remaining_time)
                time_remaining.set(f"Time remaining: {formatted_time}")
    
    elapsed_time = time.time() - start_time
    formatted_elapsed_time = format_time(elapsed_time)
    time_remaining.set(f"Time elapsed: {formatted_elapsed_time}")
    messagebox.showinfo("Done", "File decrypted successfully!")

def select_file(operation, progress, time_remaining):
    file_path = filedialog.askopenfilename()
    if file_path:
        progress['value'] = 0
        time_remaining.set("Time remaining: calculating...")
        thread = threading.Thread(target=process_file, args=(file_path, operation, progress, time_remaining))
        thread.start()

def process_file(file_path, operation, progress, time_remaining):
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
