import base64
import hashlib
import os
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptoUtils:
    """Utilities for RSA and DES encryption/decryption"""
    
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Tạo cặp khóa RSA"""
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key, key
    
    @staticmethod
    def generate_des_key():
        """Tạo khóa DES 8 bytes"""
        return get_random_bytes(8)
    
    @staticmethod
    def encrypt_des_cbc(data, key, iv=None):
        """Mã hóa dữ liệu bằng DES-CBC"""
        if iv is None:
            iv = get_random_bytes(8)
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        
        # Pad dữ liệu về bội số của 8 bytes
        padded_data = pad(data, DES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        return iv + ciphertext  # Trả về IV + ciphertext
    
    @staticmethod
    def decrypt_des_cbc(encrypted_data, key):
        """Giải mã dữ liệu DES-CBC"""
        iv = encrypted_data[:8]  # 8 bytes đầu là IV
        ciphertext = encrypted_data[8:]
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_data = cipher.decrypt(ciphertext)
        
        # Unpad dữ liệu
        return unpad(padded_data, DES.block_size)
    
    @staticmethod
    def encrypt_rsa_oaep(data, public_key):
        """Mã hóa dữ liệu bằng RSA-OAEP"""
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.encrypt(data)
    
    @staticmethod
    def decrypt_rsa_oaep(encrypted_data, private_key):
        """Giải mã dữ liệu RSA-OAEP"""
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
        return cipher.decrypt(encrypted_data)
    
    @staticmethod
    def sign_rsa_pss(data, private_key):
        """Ký dữ liệu bằng RSA-PSS với SHA-256"""
        rsa_key = RSA.import_key(private_key)
        h = SHA256.new(data)
        signature = pkcs1_15.new(rsa_key).sign(h)
        return signature
    
    @staticmethod
    def verify_rsa_pss(data, signature, public_key):
        """Xác thực chữ ký RSA-PSS"""
        try:
            rsa_key = RSA.import_key(public_key)
            h = SHA256.new(data)
            pkcs1_15.new(rsa_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def calculate_sha256(data):
        """Tính hash SHA-256"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def encode_base64(data):
        """Encode dữ liệu thành base64"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def decode_base64(encoded_data):
        """Decode dữ liệu từ base64"""
        return base64.b64decode(encoded_data)

class SecureMessageHandler:
    """Xử lý tin nhắn âm thanh bảo mật"""
    
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key
        self.session_keys = {}  # {peer_id: des_key}
    
    def set_keys(self, private_key, public_key):
        """Thiết lập cặp khóa RSA"""
        self.private_key = private_key
        self.public_key = public_key
    
    def create_session_key(self, peer_id):
        """Tạo khóa session DES cho peer"""
        des_key = CryptoUtils.generate_des_key()
        self.session_keys[peer_id] = des_key
        return des_key
    
    def encrypt_voice_message(self, audio_data, peer_id):
        """Mã hóa tin nhắn âm thanh
        
        Returns:
            dict: {
                'cipher': base64_encoded_ciphertext,
                'hash': sha256_hash,
                'sig': base64_encoded_signature
            }
        """
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key found for peer {peer_id}")
        
        des_key = self.session_keys[peer_id]
        
        # Mã hóa audio bằng DES-CBC
        encrypted_audio = CryptoUtils.encrypt_des_cbc(audio_data, des_key)
        
        # Tính hash của ciphertext
        audio_hash = CryptoUtils.calculate_sha256(encrypted_audio)
        
        # Ký hash bằng RSA
        signature = CryptoUtils.sign_rsa_pss(audio_hash.encode(), self.private_key)
        
        return {
            'cipher': CryptoUtils.encode_base64(encrypted_audio),
            'hash': audio_hash,
            'sig': CryptoUtils.encode_base64(signature)
        }
    
    def decrypt_voice_message(self, encrypted_message, peer_id, peer_public_key):
        """Giải mã tin nhắn âm thanh
        
        Args:
            encrypted_message: dict với keys 'cipher', 'hash', 'sig'
            peer_id: ID của người gửi
            peer_public_key: Public key của người gửi
            
        Returns:
            bytes: Dữ liệu audio đã giải mã, hoặc None nếu xác thực thất bại
        """
        try:
            # Decode dữ liệu từ base64
            cipher_data = CryptoUtils.decode_base64(encrypted_message['cipher'])
            signature = CryptoUtils.decode_base64(encrypted_message['sig'])
            received_hash = encrypted_message['hash']
            
            # Kiểm tra hash
            calculated_hash = CryptoUtils.calculate_sha256(cipher_data)
            if calculated_hash != received_hash:
                print(f"Hash verification failed for message from {peer_id}")
                return None
            
            # Xác thực chữ ký
            if not CryptoUtils.verify_rsa_pss(received_hash.encode(), signature, peer_public_key):
                print(f"Signature verification failed for message from {peer_id}")
                return None
            
            # Giải mã audio
            if peer_id not in self.session_keys:
                print(f"No session key found for peer {peer_id}")
                return None
                
            des_key = self.session_keys[peer_id]
            decrypted_audio = CryptoUtils.decrypt_des_cbc(cipher_data, des_key)
            
            return decrypted_audio
            
        except Exception as e:
            print(f"Error decrypting message from {peer_id}: {e}")
            return None
    
    def create_key_exchange_package(self, peer_id, peer_public_key, metadata=None):
        """Tạo gói trao đổi khóa
        
        Returns:
            dict: {
                'signed_info': base64_encoded_signature,
                'encrypted_des_key': base64_encoded_encrypted_key
            }
        """
        # Tạo khóa DES mới cho session
        des_key = self.create_session_key(peer_id)
        
        # Tạo metadata để ký (user_id + timestamp)
        if metadata is None:
            import time
            metadata = f"{peer_id}:{int(time.time())}"
        
        # Ký metadata
        signature = CryptoUtils.sign_rsa_pss(metadata.encode(), self.private_key)
        
        # Mã hóa khóa DES bằng public key của peer
        encrypted_des_key = CryptoUtils.encrypt_rsa_oaep(des_key, peer_public_key)
        
        return {
            'signed_info': CryptoUtils.encode_base64(signature),
            'encrypted_des_key': CryptoUtils.encode_base64(encrypted_des_key),
            'metadata': metadata
        }
    
    def process_key_exchange(self, key_package, peer_id, peer_public_key):
        """Xử lý gói trao đổi khóa từ peer
        
        Returns:
            bool: True nếu thành công, False nếu thất bại
        """
        try:
            # Decode dữ liệu
            signature = CryptoUtils.decode_base64(key_package['signed_info'])
            encrypted_des_key = CryptoUtils.decode_base64(key_package['encrypted_des_key'])
            metadata = key_package['metadata']
            
            # Xác thực chữ ký metadata
            if not CryptoUtils.verify_rsa_pss(metadata.encode(), signature, peer_public_key):
                print(f"Key exchange signature verification failed from {peer_id}")
                return False
            
            # Giải mã khóa DES
            des_key = CryptoUtils.decrypt_rsa_oaep(encrypted_des_key, self.private_key)
            
            # Lưu khóa session
            self.session_keys[peer_id] = des_key
            
            print(f"Key exchange successful with {peer_id}")
            return True
            
        except Exception as e:
            print(f"Error processing key exchange from {peer_id}: {e}")
            return False
    
    def get_session_key(self, peer_id):
        """Lấy khóa session cho peer"""
        return self.session_keys.get(peer_id)
    
    def remove_session_key(self, peer_id):
        """Xóa khóa session của peer"""
        if peer_id in self.session_keys:
            del self.session_keys[peer_id]