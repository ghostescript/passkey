import base64
import json
import datetime # Import datetime module
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ANSI escape codes for colors
BOLD_GREEN = '\033[1;32m' # Bold Green
RED = '\033[91m' # Red color
BRIGHT_RED = '\033[1;91m' # Bright RED
ENDC = '\033[0m'

def log_decrypted_message(encrypted_filename, decrypted_message):
    """Logs the decrypted message with a timestamp."""
    log_file_path = "decrypted_messages.log"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file_path, "a") as log_f:
        log_f.write(f"[{timestamp}] Decrypted message from file '{encrypted_filename}':\n")
        log_f.write("--- Decrypted Content Start ---\n")
        log_f.write(decrypted_message)
        log_f.write("\n--- Decrypted Content End ---\n\n")

def load_private_key(filepath):
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Assuming no password for simplicity, can be added
            backend=default_backend()
        )
    return private_key

def decrypt_message(private_key_filepath, encrypted_data, encrypted_file_name):
    private_key = load_private_key(private_key_filepath)

    # Decode base64 strings
    encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_aes_key"])
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    # Decrypt the AES key using the recipient's RSA private key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the message using AES GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_message_str = plaintext.decode('utf-8')

    print(f"\n{BOLD_GREEN}--- Decrypted Message ---{ENDC}")
    print(f"\n{decrypted_message_str}")

    log_decrypted_message(encrypted_file_name, decrypted_message_str) # Log the decrypted message

if __name__ == "__main__":
    banner = f"""{BRIGHT_RED}
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
        #print("Please ensure you have the 'cryptography' library installed: pip install cryptography")

        private_key_path = input("File path to your private key < private_key.pem > ")
        encrypted_file_name = input("Enter the 10-digit filename received (e.g., 1234567890.json): ")

        try:
            with open(encrypted_file_name, "r") as f:
                encrypted_data = json.load(f)

            decrypt_message(private_key_path, encrypted_data, encrypted_file_name)
        except FileNotFoundError:
            print(f"Error: File '{encrypted_file_name}' not found.")
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON from '{encrypted_file_name}'. Is it a valid encrypted message file?")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    except KeyboardInterrupt:
        print(f"\n\n{RED}Process Terminated...{ENDC}")
        exit(1)
