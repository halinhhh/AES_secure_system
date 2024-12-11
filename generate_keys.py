from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

def generate_keys():
    # Get the directory where the script is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate RSA key pair
    key = RSA.generate(2048)
    
    # Save private key with full path
    private_key = key.export_key()
    private_key_path = os.path.join(current_dir, "private.pem")
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    print(f"[+] Private key saved to: {private_key_path}")
    
    # Save public key with full path
    public_key = key.publickey().export_key()
    public_key_path = os.path.join(current_dir, "public.pem")
    with open(public_key_path, "wb") as f:
        f.write(public_key)
    print(f"[+] Public key saved to: {public_key_path}")
    
    print("[+] RSA keys generated successfully!")

if __name__ == "__main__":
    generate_keys()