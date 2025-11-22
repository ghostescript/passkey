from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ANSI escape codes for colors
CYAN = '\033[96m'
BOLD_GREEN = '\033[1;32m' # Bold Green
BRIGHT_WHITE = '\033[97m' # Bright White
ENDC = '\033[0m'

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"\n{CYAN} >>> RSA {BOLD_GREEN}private_key.pem{ENDC}{CYAN} and {BOLD_GREEN}public_key.pem{ENDC}{CYAN} generated. Send your {BOLD_GREEN}public_key.pem{ENDC}{CYAN} file to the message sender to save in their tool directory. Manage your keys for secure messaging. Generate new keys anytime. <<<{ENDC}\n")

if __name__ == "__main__":
    banner = f"""{BOLD_GREEN}
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
    generate_rsa_keys()
