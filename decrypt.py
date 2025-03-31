from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os

# Load AES key and IV from file
def load_key():
    key_file_path = "aes_key.bin"
    if not os.path.exists(key_file_path):
        raise FileNotFoundError("❌ Key file 'aes_key.bin' not found! Ensure you have the correct key.")

    with open(key_file_path, "rb") as key_file:
        key_iv = key_file.read()
        if len(key_iv) != 32:  # Ensure key + IV is 32 bytes
            raise ValueError("❌ Invalid key file! Ensure correct key is used.")
    
    return key_iv[:16], key_iv[16:]

# Decrypt a single file
def decrypt_file(file_path, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        # Write decrypted data only if successful
        with open(file_path, "wb") as f:
            f.write(decrypted_data)

        # Restore original file name
        new_name = file_path.replace(".locked", "")
        if not os.path.exists(new_name):  # Prevent overwriting existing files
            os.rename(file_path, new_name)
            print(f"🔓 Successfully decrypted: {new_name}")
        else:
            print(f"⚠️ Skipping rename (file already exists): {new_name}")

    except (ValueError, OSError) as e:
        print(f"❌ Error decrypting {file_path}: {e}")

# Decrypt all files in a folder
def decrypt_files(directory):
    try:
        key, iv = load_key()
    except (FileNotFoundError, ValueError) as e:
        print(e)
        return  # Stop execution if key file is missing or invalid

    decrypted_any = False

    for file in os.listdir(directory):
        file_path = os.path.join(directory, file)

        # Only decrypt .locked files
        if os.path.isfile(file_path) and file.endswith(".locked"):
            decrypt_file(file_path, key, iv)
            decrypted_any = True

    # Delete ransom note if it exists
    ransom_note = os.path.join(directory, "READ_THIS.txt")
    if os.path.exists(ransom_note):
        os.remove(ransom_note)

    if decrypted_any:
        print("✅ All files decrypted successfully!")
    else:
        print("⚠️ No encrypted files found in the directory.")

# Run decryption
if __name__ == "__main__":
    decrypt_files(r"C:\Users\shrad\test_folder")  # Change to your actual folder
