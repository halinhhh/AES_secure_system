import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import json
import os
import sys
import time
import traceback

class SecureClient:
    def __init__(self, host='localhost', port=8888):
        print(f"\n{'='*50}")
        print("SECURE CLIENT INITIALIZATION")
        print(f"{'='*50}")
        print(f"[*] Setting up client for {host}:{port}")
        
        self.host = host
        self.port = port
        self.socket = None
        
        # Get current directory
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"[*] Working directory: {self.current_dir}")
        
        # Load keys
        try:
            # Load public key
            with open(os.path.join(self.current_dir, "public.pem"), "rb") as f:
                self.server_public_key = RSA.import_key(f.read())
            print("[+] Server public key loaded")
            
            # Load private key
            with open(os.path.join(self.current_dir, "private.pem"), "rb") as f:
                self.private_key = RSA.import_key(f.read())
            print("[+] Private key loaded")
            
        except Exception as e:
            print(f"[!] Error loading keys: {str(e)}")
            raise

    def handshake(self):
        try:
            print("[*] Starting handshake process")
            
            # Step 1: Client Hello
            client_nonce = get_random_bytes(32).hex()
            client_hello = {
                'nonce': client_nonce,
                'timestamp': time.time(),
                'client_id': str(os.getpid())
            }
            self.socket.send(json.dumps(client_hello).encode())
            print(f"[+] Sent Client Hello: {client_hello}")
            
            # Step 2: Receive Server Hello
            server_hello = self.socket.recv(1024)
            server_data = json.loads(server_hello.decode())
            server_nonce = server_data['nonce']
            print(f"[+] Received Server Hello: {server_data}")
            
            # Verify timestamp
            if abs(time.time() - server_data['timestamp']) > 300:
                raise Exception("Invalid server timestamp")
            
            # Step 3: Client Authentication
            hash_obj = SHA256.new((client_nonce + server_nonce).encode())
            signature = pkcs1_15.new(self.private_key).sign(hash_obj)
            
            # Send client verification
            auth_data = signature + self.private_key.publickey().export_key()
            self.socket.send(auth_data)
            print("[+] Sent client verification")
            
            # Step 4: Verify Server
            server_signature = self.socket.recv(256)
            hash_obj = SHA256.new((server_nonce + client_nonce).encode())
            
            try:
                pkcs1_15.new(self.server_public_key).verify(
                    hash_obj, 
                    server_signature
                )
                print("[+] Server verification successful")
            except Exception as e:
                raise Exception(f"Server verification failed: {str(e)}")
            
            # Generate session keys
            master_secret = SHA256.new(
                (client_nonce + server_nonce + "master_key").encode()
            ).digest()
            
            session_key = SHA256.new(
                (master_secret + b"session_key")
            ).digest()
            
            return session_key
            
        except Exception as e:
            print(f"[!] Handshake failed: {str(e)}")
            return None

    def send_file(self, file_path):
        try:
            print(f"\n{'='*50}")
            print("STARTING FILE TRANSMISSION")
            print(f"{'='*50}")
            
            # Verify file exists
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            # Create socket connection
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            print(f"[+] Connected to {self.host}:{self.port}")
            
            # Perform handshake
            session_key = self.handshake()
            if not session_key:
                raise Exception("Handshake failed")
            
            print("[+] Handshake completed successfully")
            
            # Read file
            with open(file_path, 'rb') as f:
                file_data = f.read()
            print(f"[+] Read {len(file_data)} bytes from file")
            
            # Create signature
            hash_obj = SHA256.new(file_data)
            signature = pkcs1_15.new(self.private_key).sign(hash_obj)
            print("[+] Created digital signature")
            
            # Encrypt file data
            iv = get_random_bytes(16)
            cipher_aes = AES.new(session_key[:16], AES.MODE_CBC, iv)
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher_aes.encrypt(padded_data)
            final_data = iv + encrypted_data
            print(f"[+] Data encrypted: {len(final_data)} bytes")
            
            # Prepare and send metadata
            metadata = {
                'file_size': len(final_data),
                'signature': signature.hex(),
                'file_extension': os.path.splitext(file_path)[1]
            }
            metadata_bytes = json.dumps(metadata).encode()
            self.socket.send(len(metadata_bytes).to_bytes(4, byteorder='big'))
            self.socket.send(metadata_bytes)
            print("[+] Metadata sent")
            
            # Send encrypted data
            self.socket.sendall(final_data)
            print(f"[+] Sent {len(final_data)} bytes")
            
            # Wait for server response
            try:
                result = self.socket.recv(7)
                if result == b"SUCCESS":
                    print("[+] Server verified file successfully")
                else:
                    print("[!] Server verification failed")
            except socket.timeout:
                print("[!] Timeout waiting for server response")
            
        except socket.timeout:
            print("[!] Connection timed out")
            print("[!] Please verify that the server is running")
        except ConnectionRefusedError:
            print(f"[!] Connection refused by {self.host}:{self.port}")
            print("[!] Please verify that the server is running and port is correct")
        except Exception as e:
            print(f"[!] Error during transmission: {str(e)}")
            print("[!] Full traceback:")
            traceback.print_exc()
        finally:
            if self.socket:
                self.socket.close()
                print("[*] Connection closed")

if __name__ == "__main__":
    try:
        print(f"\n{'='*50}")
        print("SECURE FILE TRANSFER CLIENT")
        print(f"{'='*50}")
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        image_path = os.path.join(current_dir, "input.jpg")
        
        print(f"[*] Starting in directory: {current_dir}")
        print(f"[*] Looking for image at: {image_path}")
        print("\n[*] Directory contents:")
        for file in os.listdir(current_dir):
            print(f"  - {file}")
        
        if not os.path.exists(image_path):
            print(f"\n[!] Error: input.jpg not found!")
            sys.exit(1)
            
        print("\n[*] Initializing client...")
        client = SecureClient()
        print("\n[*] Starting file transfer...")
        client.send_file(image_path)
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {str(e)}")
        print("[!] Full traceback:")
        traceback.print_exc()
    finally:
        print(f"\n{'='*50}")
        print("CLIENT SHUTDOWN")
        print(f"{'='*50}")
    
    sys.exit(0)