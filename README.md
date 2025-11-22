# passkey
This tool provides a basic framework for sending and receiving encrypted messages between two machines using RSA for key exchange and AES-256 GCM for message encryption.

## Clone Repository 
```bash
git clone https://github.com/ghostescript/passkey
cd passkey
```

## Virtual Environment 
```bash
python -m venv venv
source venv/bin/activate
```

## Prerequisites

Before using the tool, you need to install the `cryptography` library.

```bash
pip install cryptography
```

## How to Use

Follow these steps to generate keys, encrypt a message, and decrypt it.

### Step 1: Generate RSA Keys (Receiver's Side)

The receiver needs to generate a pair of RSA keys: a private key and a public key. The public key will be shared with the sender, while the private key must be kept secret by the receiver.

1.  Navigate to the `passkey` directory:
    ```bash
    cd passkey
    ```
2.  Run the `generate_keys.py` script:
    ```bash
    python generate_keys.py
    ```
    This will create two files in the current directory: `private_key.pem` and `public_key.pem`.
    *   **`private_key.pem`**: Keep this file secure and do not share it. It's essential for decrypting messages.
    *   **`public_key.pem`**: Share this file with the person who will be sending you encrypted messages.

### Step 2: Send an Encrypted Message (Sender's Side)

The sender uses the receiver's `public_key.pem` to encrypt their message.

1.  Ensure you have the receiver's `public_key.pem` file. Place it in the same directory as `sender.py` or provide its full path.
2.  Navigate to the `passkey` directory:
    ```bash
    cd passkey
    ```
3.  Run the `sender.py` script:
    ```bash
    python sender.py
    ```
4.  The script will prompt you for:
    *   The path to the recipient's public key (e.g., `public_key.pem`).
    *   Whether you want to type the message directly or provide a message file.
5.  After entering the information, the script will generate a random 10-digit filename (e.g., `1234567890.json`) and save all the encrypted message details into this JSON file.
    The script will print the generated filename. You need to securely transmit this file to the receiver.
    **Logging**: Each time an encrypted file is created, an entry with a timestamp and the full content of the encrypted JSON file will be added to `encrypted_keys.log` in the same directory.
    **WARNING**: Logging the full content of encrypted files can lead to very large log files and, depending on your security model, might expose sensitive encrypted data if the log file itself is not adequately protected. Consider disabling this feature or ensuring proper log management if this is a concern.

### Step 3: Receive and Decrypt the Message (Receiver's Side)

The receiver uses their `private_key.pem` and the 10-digit JSON file received from the sender to decrypt the message.

1.  Ensure you have your `private_key.pem` file in the same directory as `receiver.py` or provide its full path.
2.  Ensure the encrypted message file (e.g., `1234567890.json`) is in the same directory as `receiver.py` or provide its full path.
3.  Navigate to the `passkey` directory:
    ```bash
    cd passkey
    ```
4.  Run the `receiver.py` script:
    ```bash
    python receiver.py
    ```
5.  The script will prompt you for:
    *   The path to your private key (e.g., `private_key.pem`).
    *   The 10-digit filename (e.g., `1234567890.json`) received from the sender.
6.  After entering all the required information, the script will output the original decrypted message.
    **Logging**: Each time a message is successfully decrypted, an entry with a timestamp and the decrypted message content will be added to `decrypted_messages.log` in the same directory.
    **WARNING**: Logging decrypted message content can expose sensitive information if the log file itself is not adequately protected. Consider disabling this feature or ensuring proper log management if this is a concern.

<br>

## Updated On
``Nov 22, 2025``

<br>
