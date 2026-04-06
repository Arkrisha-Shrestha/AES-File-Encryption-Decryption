import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256


def get_key(password: str) -> bytes:
    return SHA256.new(password.encode()).digest()


def encrypt_file(file_path: str, password: str):
    key = get_key(password)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = iv + cipher.encrypt(pad(plaintext, AES.block_size))

    output_path = file_path + ".enc"
    with open(output_path, 'wb') as f:
        f.write(ciphertext)

    return output_path


def decrypt_file(file_path: str, password: str):
    key = get_key(password)

    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    if len(ciphertext) < 16:
        raise ValueError("Invalid encrypted file.")

    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    if file_path.endswith(".enc"):
        output_path = file_path[:-4]
    else:
        output_path = file_path + ".dec"

    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return output_path


class FileEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES File Encryption & Decryption Tool")
        self.root.geometry("520x260")
        self.root.resizable(False, False)

        self.file_path = tk.StringVar()
        self.password = tk.StringVar()

        title = tk.Label(
            root,
            text="AES File Encryption & Decryption",
            font=("Arial", 16, "bold")
        )
        title.pack(pady=10)

        frame = tk.Frame(root)
        frame.pack(pady=10, padx=15, fill="x")

        tk.Label(frame, text="Selected File:", font=("Arial", 11)).grid(row=0, column=0, sticky="w")
        tk.Entry(frame, textvariable=self.file_path, width=45, font=("Arial", 10)).grid(row=1, column=0, padx=(0, 10), pady=5)
        tk.Button(frame, text="Browse", width=10, command=self.browse_file).grid(row=1, column=1)

        tk.Label(frame, text="Password:", font=("Arial", 11)).grid(row=2, column=0, sticky="w", pady=(10, 0))
        tk.Entry(frame, textvariable=self.password, show="*", width=45, font=("Arial", 10)).grid(row=3, column=0, pady=5, padx=(0, 10))
        tk.Button(frame, text="Show/Hide", width=10, command=self.toggle_password).grid(row=3, column=1)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)

        tk.Button(
            button_frame,
            text="Encrypt File",
            width=18,
            height=2,
            command=self.handle_encrypt
        ).grid(row=0, column=0, padx=10)

        tk.Button(
            button_frame,
            text="Decrypt File",
            width=18,
            height=2,
            command=self.handle_decrypt
        ).grid(row=0, column=1, padx=10)

        self.password_visible = False

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def toggle_password(self):
        entries = self.root.winfo_children()
        self.password_visible = not self.password_visible

        for widget in self.root.winfo_children():
            self._toggle_entry_recursive(widget)

    def _toggle_entry_recursive(self, widget):
        if isinstance(widget, tk.Entry) and widget.cget("textvariable") == str(self.password):
            widget.config(show="" if self.password_visible else "*")
        for child in widget.winfo_children():
            self._toggle_entry_recursive(child)

    def validate_inputs(self):
        file_path = self.file_path.get().strip()
        password = self.password.get()

        if not file_path:
            messagebox.showerror("Error", "Please select a file.")
            return None, None

        if not os.path.isfile(file_path):
            messagebox.showerror("Error", "Selected file does not exist.")
            return None, None

        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return None, None

        return file_path, password

    def handle_encrypt(self):
        file_path, password = self.validate_inputs()
        if not file_path:
            return

        try:
            output_path = encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File encrypted successfully.\nSaved as:\n{output_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed.\n{str(e)}")

    def handle_decrypt(self):
        file_path, password = self.validate_inputs()
        if not file_path:
            return

        try:
            output_path = decrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File decrypted successfully.\nSaved as:\n{output_path}")
        except ValueError:
            messagebox.showerror("Error", "Wrong password or corrupted file.")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed.\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptionApp(root)
    root.mainloop()