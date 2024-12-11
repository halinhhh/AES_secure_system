# server.py
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import uuid
import json
import os
import sys
import time

class SecureServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Get current directory
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Load RSA keys
        try:
            with open(os.path.join(self.current_dir, "private.pem"), "rb") as f:
                self.private_key = RSA.import_key(f.read())
            print("[+] RSA keys loaded successfully")
        except Exception as e:
            print(f"[!] Error loading RSA keys: {str(e)}")
            raise

    def handshake(self, client_socket):
        try:
            print("[*] Starting handshake process")
            
            # Step 1: Receive Client Hello
            client_hello = client_socket.recv(1024)
            client_data = json.loads(client_hello.decode())
            client_nonce = client_data['nonce']
            client_timestamp = client_data['timestamp']
            
            print(f"[+] Received Client Hello: {client_data}")
            
            # Step 2: Server Hello
            server_nonce = get_random_bytes(32).hex()
            server_hello = {
                'nonce': server_nonce,
                'timestamp': time.time(),
                'supported_ciphers': ['AES-256-CBC', 'AES-128-CBC'],
                'supported_hash': ['SHA256', 'SHA512']
            }
            client_socket.send(json.dumps(server_hello).encode())
            print(f"[+] Sent Server Hello: {server_hello}")
            
            # Step 3: Receive client response and verify
            client_auth_data = client_socket.recv(2048)  # Increased buffer size
            signature = client_auth_data[:256]
            public_key_data = client_auth_data[256:]
            client_pubkey = RSA.import_key(public_key_data)
            
            # Verify client signature
            hash_obj = SHA256.new((client_nonce + server_nonce).encode())
            try:
                pkcs1_15.new(client_pubkey).verify(hash_obj, signature)
                print("[+] Client verification successful")
            except Exception as e:
                raise Exception(f"Client verification failed: {str(e)}")
            
            # Step 4: Server authentication
            hash_obj = SHA256.new((server_nonce + client_nonce).encode())
            server_signature = pkcs1_15.new(self.private_key).sign(hash_obj)
            
            # Generate session keys
            master_secret = SHA256.new(
                (client_nonce + server_nonce + "master_key").encode()
            ).digest()
            
            session_key = SHA256.new(
                (master_secret + b"session_key")
            ).digest()
            
            # Send server verification
            client_socket.send(server_signature)
            print("[+] Sent server verification")
            
            return session_key
            
        except Exception as e:
            print(f"[!] Handshake failed: {str(e)}")
            return None

    def handle_client(self, client_socket):
        try:
            # Perform handshake
            session_key = self.handshake(client_socket)
            if not session_key:
                raise Exception("Handshake failed")
            print("[+] Handshake completed successfully")
            
            # Receive metadata size
            metadata_size_bytes = client_socket.recv(4)
            if not metadata_size_bytes:
                raise Exception("No metadata size received")
            
            metadata_size = int.from_bytes(metadata_size_bytes, byteorder='big')
            print(f"[+] Expecting metadata size: {metadata_size}")
            
            # Receive metadata
            metadata_bytes = client_socket.recv(metadata_size)
            if not metadata_bytes:
                raise Exception("No metadata received")
            
            metadata = json.loads(metadata_bytes.decode())
            print("[+] Received metadata:", metadata)
            
            file_size = metadata['file_size']
            signature = bytes.fromhex(metadata['signature'])
            
            # Receive encrypted data
            received_data = b''
            remaining = file_size
            
            while remaining > 0:
                chunk = client_socket.recv(min(4096, remaining))
                if not chunk:
                    break
                received_data += chunk
                remaining -= len(chunk)
                print(f"[+] Received {len(received_data)}/{file_size} bytes")
            
            # Extract IV and encrypted data
            iv = received_data[:16]
            encrypted_data = received_data[16:]
            
            # Decrypt using AES with session key
            cipher_aes = AES.new(session_key[:16], AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)
            print("[+] Data decrypted successfully")
            
            # Verify integrity with SHA-256
            hash_obj = SHA256.new(decrypted_data)
            
            try:
                # Verify signature
                pkcs1_15.new(self.private_key.publickey()).verify(
                    hash_obj,
                    signature
                )
                print("[+] Signature verified successfully")
                
                # Create output directory if it doesn't exist
                output_dir = os.path.join(self.current_dir, "output")
                os.makedirs(output_dir, exist_ok=True)
                
                # Save decrypted file
                output_filename = os.path.join(
                    output_dir, 
                    f"decrypted_{str(uuid.uuid4())[:8]}.jpg"
                )
                with open(output_filename, 'wb') as f:
                    f.write(decrypted_data)
                
                print(f"[+] File saved as {output_filename}")
                
                # Send success confirmation
                client_socket.send(b"SUCCESS")
                
            except (ValueError, TypeError) as e:
                print(f"[!] Signature verification failed: {str(e)}")
                client_socket.send(b"FAILURE")
            
        except Exception as e:
            print(f"[!] Error handling client: {str(e)}")
            try:
                client_socket.send(b"FAILURE")
            except:
                pass
        finally:
            client_socket.close()

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"[*] Server listening on {self.host}:{self.port}")
            
            while True:
                client_socket, addr = self.server_socket.accept()
                print(f"[+] Connection from {addr}")
                
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.daemon = True
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
            self.cleanup()
        except Exception as e:
            print(f"[!] Server error: {str(e)}")
            self.cleanup()
            sys.exit(1)

    def cleanup(self):
        try:
            self.server_socket.close()
            print("[*] Server socket closed")
        except:
            pass

if __name__ == "__main__":
    server = None
    try:
        server = SecureServer()
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
        if server:
            server.cleanup()
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        if server:
            server.cleanup()
    sys.exit(0)