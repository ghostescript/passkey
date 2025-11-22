from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import random
import datetime # Import datetime module

# ANSI escape codes for colors
YELLOW = '\033[93m'
RED = '\033[91m' # Red color
BOLD_GREEN = '\033[1;32m' # Bold Green
BRIGHT_BLUE = '\033[94m' # Bright Blue
ENDC = '\033[0m'

def log_encrypted_file(filename):
    """
    Logs the creation of an encrypted file with a timestamp and its content.
    WARNING: Logging file content can lead to large log files and expose sensitive encrypted data.
    """
    log_file_path = "encrypted_keys.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_content = ""
    try:
        with open(filename, "r") as f:
            file_content = f.read()
    except Exception as e:
        file_content = f"Error reading file content for log: {e}"

    with open(log_file_path, "a") as log_f:
        log_f.write(f"[{timestamp}] Encrypted file created: {filename}\n")
        log_f.write("--- File Content Start ---\n")
        log_f.write(file_content)
        log_f.write("\n--- File Content End ---\n\n")

def load_public_key(filepath):
    try:
        with open(filepath, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except FileNotFoundError:
        print(f"\n{YELLOW}Error: The path to the recipient's public key (e.g., public_key.pem) NOT FOUND...{ENDC}\n")
        exit(1) # Exit the program if the public key is not found

def encrypt_message(public_key_filepath, message):
    public_key = load_public_key(public_key_filepath)

    # Generate a random AES key
    aes_key = os.urandom(32) # 256-bit key

    # Encrypt the message using AES GCM
    iv = os.urandom(16) # Initialization vector
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag

    # Encrypt the AES key using the recipient's RSA public key
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Encode everything to base64 for safe transmission
    encoded_encrypted_aes_key = base64.b64encode(encrypted_aes_key).decode('utf-8')
    encoded_iv = base64.b64encode(iv).decode('utf-8')
    encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    encoded_tag = base64.b64encode(tag).decode('utf-8')

    # Generate a random 10-digit filename
    filename = ''.join(random.choices('0123456789', k=10)) + ".json"

    encrypted_data = {
        "encrypted_aes_key": encoded_encrypted_aes_key,
        "iv": encoded_iv,
        "ciphertext": encoded_ciphertext,
        "tag": encoded_tag
    }

    with open(filename, "w") as f:
        json.dump(encrypted_data, f, indent=4)

    log_encrypted_file(filename) # Log the created file

    print(f"{BOLD_GREEN}\nEncrypted message saved to file: {filename}\n\nPlease send this file to the receiver.{ENDC}")

if __name__ == "__main__":
    banner = f"""{BRIGHT_BLUE}
=================================================
=============================  ==================
=============================  ==================
=============================  ==================
=    ====   ====   ====   ===  =  ===   ===  =  =
=  =  ==  =  ==  =  ==  =  ==    ===  =  ==  =  =
=  =  =====  ===  =====  ====   ====     ===    =
=    ====    ====  =====  ===    ===  ========  =
=  =====  =  ==  =  ==  =  ==  =  ==  =  ==  =  =
=  ======    ===   ====   ===  =  ===   ====   ==
=================================================
               --- ghostescript ---
{ENDC}"""
    print(banner)
    try:


        public_key_path = input("\nFile path to the recipient's public key < public_key.pem > ")

        message_source_choice = input("\nEnter '1' to type the message directly, or '2' to provide a message file: ")

        message_content = ""
        if message_source_choice == '1':
            print("\nEnter your message to encrypt (press Enter twice to finish):")
            message_lines = []
            while True:
                line = input()
                if not line:
                    break
                message_lines.append(line)
            message_content = "\n".join(message_lines)
        elif message_source_choice == '2':
            message_filepath = input("\nEnter the path to the message file: ")
            try:
                with open(message_filepath, "r") as f:
                    message_content = f.read()
            except FileNotFoundError:
                print(f"\n{YELLOW}Error: Message file '{message_filepath}' not found.{ENDC}")
                exit(1)
            except Exception as e:
                print(f"\n{YELLOW}Error reading message file: {e}{ENDC}")
                exit(1)
        else:
            print(f"\n{YELLOW}Invalid choice. Exiting.{ENDC}")
            exit(1)

        encrypt_message(public_key_path, message_content)
    except KeyboardInterrupt:
        print(f"\n\n{RED}Process Terminated...{ENDC}")
        exit(1)
