# crypto.py
import os
import hashlib
import hmac  # Sử dụng hmac thay vì hashlib để dùng compare_digest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

class ECCSecureStorage:
    def __init__(self):
        # Thiết lập đường dẫn lưu trữ khóa trong thư mục 'keys'
        self.private_key_path = f"{os.path.dirname(__file__)}/keys/private_key.pem"
        self.public_key_path = f"{os.path.dirname(__file__)}/keys/public_key.pem"
        os.makedirs("keys", exist_ok=True)

    def generate_keys(self):
        """Tạo cặp khóa ECC (Private Key và Public Key) nếu chưa tồn tại."""
        if os.path.exists(self.private_key_path):
            print("🔑 Đã tồn tại khóa ECC")
            return
        
        # Sử dụng đường cong SECP384R1 cho độ bảo mật cao
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        # Lưu Private Key dưới định dạng PEM
        with open(self.private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        # Lưu Public Key dưới định dạng PEM
        with open(self.public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("✅ Đã tạo ECC Key Pair (SECP384R1)")

    def load_private_key(self):
        """Tải Private Key từ file."""
        with open(self.private_key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_public_key(self):
        """Tải Public Key từ file."""
        with open(self.public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    # ==================== ECIES: BỌC KHÓA AES (UPLOAD) ====================
    def ecies_encrypt_aes_key(self, aes_key: bytes):
        """Bọc khóa AES bằng thuật toán ECIES (ECC + AES-GCM)."""
        private_key = self.load_private_key()
        public_key = private_key.public_key()

        # Tạo cặp khóa tạm thời (ephemeral key) cho phiên làm việc
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()

        # Thực hiện trao đổi khóa Diffie-Hellman (ECDH) để tạo shared_secret
        shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)
        
        # Sử dụng HKDF để tạo ra khóa mã hóa (enc_key) và khóa xác thực (mac_key)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"ECIES-AES-WRAP")
        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:32]
        mac_key = key_material[32:]

        # Mã hóa khóa AES gốc bằng AES-GCM
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(aes_key) + encryptor.finalize()
        tag = encryptor.tag

        # Tạo mã xác thực tin nhắn (MAC) để đảm bảo tính toàn vẹn
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        mac_data = ephemeral_pub_bytes + ciphertext + tag
        mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()

        return {
            "ephemeral_public": ephemeral_pub_bytes,
            "ciphertext": ciphertext,
            "iv": iv,
            "tag": tag,
            "mac": mac
        }

    # ==================== ECIES: GIẢI MÃ KHÓA AES (DOWNLOAD) ====================
    def ecies_decrypt_aes_key(self, wrapped: dict):
        """Giải mã lớp bọc ECC để lấy lại khóa AES gốc."""
        private_key = self.load_private_key()
        
        # Tải lại ephemeral public key từ dữ liệu đã lưu
        ephemeral_public = serialization.load_pem_public_key(wrapped["ephemeral_public"])
        
        # Tái tạo shared_secret thông qua ECDH
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
        
        # Tái tạo enc_key và mac_key thông qua HKDF
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"ECIES-AES-WRAP")
        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:32]
        mac_key = key_material[32:]

        # Kiểm tra tính toàn vẹn dữ liệu (MAC) sử dụng hmac.compare_digest để chống timing attacks
        mac_data = wrapped["ephemeral_public"] + wrapped["ciphertext"] + wrapped["tag"]
        calculated_mac = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
        
        if not hmac.compare_digest(calculated_mac, wrapped["mac"]):
            raise Exception("❌ Lỗi: Dữ liệu khóa bị thay đổi hoặc giả mạo (MAC mismatch)!")

        # Giải mã ciphertext để lấy khóa AES gốc
        cipher = Cipher(algorithms.AES(enc_key), modes.GCM(wrapped["iv"], wrapped["tag"]))
        decryptor = cipher.decryptor()
        aes_key = decryptor.update(wrapped["ciphertext"]) + decryptor.finalize()
        
        return aes_key

    # ==================== ECDSA: KÝ SỐ (AUTHENTICATION) ====================
    def sign_manifest(self, manifest_bytes: bytes):
        """Ký số vào file Manifest để đảm bảo tính xác thực."""
        private_key = self.load_private_key()
        signature = private_key.sign(
            manifest_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, manifest_bytes: bytes, signature: bytes):
        """Xác minh chữ ký số của Manifest."""
        public_key = self.load_public_key()
        try:
            public_key.verify(
                signature,
                manifest_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False