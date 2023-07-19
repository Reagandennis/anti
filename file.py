import tkinter as tk
from tkinter import messagebox
import os
import hashlib

# Dictionary to store user credentials (username: password)
user_credentials = {}

def authenticate_user():
    username = entry_username.get()
    password = entry_password.get()

    if username in user_credentials and user_credentials[username] == password:
        # Successful authentication, open the main application window
        open_main_app()
    else:
        messagebox.showerror("Error", "Invalid username or password")

def open_main_app():
    # Close the login window
    login_window.destroy()

    # Create the main application window
    main_app_window = tk.Tk()
    main_app_window.title("Antivirus Scanner")

    def calculate_file_hash(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read the file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_for_viruses():
        scan_path = entry_scan_path.get()
        if not os.path.exists(scan_path):
            messagebox.showerror("Error", "Invalid directory path.")
            return

        threats_found = False
        threats_list = []

        # List all files in the scan directory and its subdirectories
        for root, _, files in os.walk(scan_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_file_hash(file_path)

                # Compare the hash with a known safe hash or a list of safe hashes
                # For simplicity, you can have a predefined set of safe hashes or known good files
                # Replace 'known_safe_hashes' with a list of known safe file hashes
                known_safe_hashes = [
                    "ad9123c4d33f1f83710ac8a5e48d1a05a60d81f7e1762d80c8a76f39db546e5d",
                    # Add more known safe hashes if needed
                ]

                if file_hash not in known_safe_hashes:
                    threats_found = True
                    threats_list.append(file_path)

        if threats_found:
            messagebox.showwarning("Scan Result", f"Threats found in the following files:\n\n{', '.join(threats_list)}")
        else:
            messagebox.showinfo("Scan Result", "No threats were detected.")

    # Add an entry for users to input the root directory path for scanning
    label_scan_path = tk.Label(main_app_window, text="Enter the root directory path to scan:")
    label_scan_path.pack()
    entry_scan_path = tk.Entry(main_app_window)
    entry_scan_path.pack()

    # Add a "Scan" button in the main application window
    scan_button = tk.Button(main_app_window, text="Scan for Viruses", command=scan_for_viruses)
    scan_button.pack()

    # ... More code for the main application window ...

    main_app_window.mainloop()

def create_account():
    username = entry_new_username.get()
    password = entry_new_password.get()

    if username and password:
        if username in user_credentials:
            messagebox.showerror("Error", "Username already exists. Please choose a different username.")
        else:
            user_credentials[username] = password
            messagebox.showinfo("Account Created", "Your account has been created successfully. You can now log in.")
    else:
        messagebox.showerror("Error", "Please enter a valid username and password.")

# Create the login window
login_window = tk.Tk()
login_window.title("Login")

# Username label and entry
label_username = tk.Label(login_window, text="Username:")
label_username.pack()
entry_username = tk.Entry(login_window)
entry_username.pack()

# Password label and entry
label_password = tk.Label(login_window, text="Password:")
label_password.pack()
entry_password = tk.Entry(login_window, show="*")
entry_password.pack()

# Login button
login_button = tk.Button(login_window, text="Login", command=authenticate_user)
login_button.pack()

# Create an account label and entries
label_new_username = tk.Label(login_window, text="New Username:")
label_new_username.pack()
entry_new_username = tk.Entry(login_window)
entry_new_username.pack()

label_new_password = tk.Label(login_window, text="New Password:")
label_new_password.pack()
entry_new_password = tk.Entry(login_window, show="*")
entry_new_password.pack()

# Create Account button
create_account_button = tk.Button(login_window, text="Create Account", command=create_account)
create_account_button.pack()

login_window.mainloop()
