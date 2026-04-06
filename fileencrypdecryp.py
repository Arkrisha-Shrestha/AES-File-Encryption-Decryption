from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import os


# 🔐 Convert password → 32-byte key
def get_key(password):
    return SHA256.new(password.encode()).digest()


def encrypt_file(file_path, password):
    key = get_key(password)
    

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = iv + cipher.encrypt(pad(plaintext, AES.block_size))

    with open(file_path + '.enc', 'wb') as f:
        f.write(ciphertext)

    print("✅ File encrypted successfully!")


def decrypt_file(file_path, password):
    key = get_key(password)

    with open(file_path, 'rb') as f:
        ciphertext = f.read()

    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)

        with open(file_path[:-4], 'wb') as f:
            f.write(plaintext)

        print("✅ File decrypted successfully!")

    except:
        print("❌ Wrong password or corrupted file!")


# 🎯 CLI Demo
if __name__ == "__main__":
    print("1. Encrypt File")
    print("2. Decrypt File")

    choice = input("Enter choice: ")
    file_path = input("Enter file path: ").strip().strip('"')
    password = input("Enter password: ")

    if choice == '1':
        encrypt_file(file_path, password)
    elif choice == '2':
        decrypt_file(file_path, password)
    else:
        print("Invalid choice")