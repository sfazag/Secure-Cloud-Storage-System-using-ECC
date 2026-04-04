# main.py
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto import ECCSecureStorage
from file_handler import split_file
from storage_simulator import save_fragment, save_manifest, load_manifest, list_files
from config import UPLOADS_PATH, DOWNLOADS_PATH, SIMULATED_CLOUD_PATH

# ====================== CẤU HÌNH ĐƯỜNG DẪN TUYỆT ĐỐI ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_PATH = os.path.join(BASE_DIR, "uploads")
DOWNLOADS_PATH = os.path.join(BASE_DIR, "downloads")
CLOUD_FRAGMENTS_DIR = os.path.join(BASE_DIR, SIMULATED_CLOUD_PATH, "fragments")

os.makedirs(UPLOADS_PATH, exist_ok=True)
os.makedirs(DOWNLOADS_PATH, exist_ok=True)

ecc = ECCSecureStorage()

def main():
    print("🔑 Đang kiểm tra / tạo khóa ECC...")
    ecc.generate_keys()
    
    print("\n" + "="*75)
    print("🚀 HỆ THỐNG MÔ PHỎNG SECURE CLOUD STORAGE USING ECC")
    print("="*75)
    print(f"📍 Thư mục dự án: {BASE_DIR}\n")

    while True:
        print("\n1. Upload file (Mã hóa AES + ECC Wrap + Fragmentation)")
        print("2. Download & Giải mã file (ECC Unwrap + Reassembly)")
        print("3. Xem danh sách file trên Cloud")
        print("4. Thoát")
        
        choice = input("\nChọn chức năng (1-4): ").strip()

        # ==================== CHỨC NĂNG 1: UPLOAD ====================
        if choice == "1":
            filename = input("Nhập tên file trong thư mục uploads/: ").strip()
            filepath = os.path.join(UPLOADS_PATH, filename)

            if not os.path.exists(filepath):
                print(f"❌ Không tìm thấy file: {filepath}")
                continue

            file_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
            print(f"🔐 Đang xử lý file: {filename}")

            # 1. Tạo khóa AES và bọc bằng ECIES (ECC)
            aes_key = os.urandom(32)
            wrapped = ecc.ecies_encrypt_aes_key(aes_key)
            wrapped_serializable = {k: v.hex() for k, v in wrapped.items()}

            # 2. Chia nhỏ file và mã hóa từng phần
            fragments, original_size = split_file(filepath)
            manifest = {
                "file_id": file_id,
                "original_filename": filename,
                "original_size": original_size,
                "fragment_count": len(fragments),
                "wrapped_aes": wrapped_serializable,
                "fragments": []
            }

            print(f"✂️  Đang mã hóa và lưu {len(fragments)} fragments...")
            for frag in fragments:
                iv = os.urandom(12)
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(frag["data"]) + encryptor.finalize()
                
                # Gói dữ liệu: IV (12b) + TAG (16b) + CIPHERTEXT
                encrypted_data = iv + encryptor.tag + ciphertext
                save_fragment(file_id, frag["index"], encrypted_data)

                manifest["fragments"].append({
                    "index": frag["index"],
                    "checksum": frag["checksum"]
                })

            # 3. Ký số Manifest bằng ECDSA
            manifest_json_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
            signature = ecc.sign_manifest(manifest_json_bytes)
            manifest["signature"] = signature.hex()

            save_manifest(file_id, manifest)
            print(f"✅ UPLOAD THÀNH CÔNG! File ID: {file_id}")

        # ==================== CHỨC NĂNG 2: DOWNLOAD ====================
        elif choice == "2":
            files = list_files()
            if not files:
                print("📭 Cloud trống, không có manifest nào.")
                continue
            
            print("\n📋 Danh sách file khả dụng:")
            for idx, f in enumerate(files):
                print(f"  {idx+1}. {f}")
            
            try:
                f_choice = input("\nChọn số thứ tự file: ").strip()
                selected_id = files[int(f_choice)-1]
                manifest = load_manifest(selected_id)

                # 1. Xác minh chữ ký ECDSA
                signature_hex = manifest.pop("signature")
                manifest_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
                if not ecc.verify_signature(manifest_bytes, bytes.fromhex(signature_hex)):
                    print("❌ CẢNH BÁO: Manifest bị giả mạo hoặc chữ ký không khớp!")
                    continue

                # 2. Giải mã khóa AES (ECC Unwrap)
                print("🔓 Đang giải mã khóa AES bằng ECC...")
                wrapped_bytes = {k: bytes.fromhex(v) for k, v in manifest["wrapped_aes"].items()}
                aes_key = ecc.ecies_decrypt_aes_key(wrapped_bytes)

                # 3. Giải mã và hợp nhất fragments
                decrypted_chunks = []
                print(f"📡 Đang tải các mảnh của {selected_id}...")
                
                for frag_info in manifest["fragments"]:
                    f_idx = frag_info["index"]
                    frag_filename = f"{selected_id}_frag_{f_idx:03d}.enc"
                    frag_path = os.path.join(CLOUD_FRAGMENTS_DIR, frag_filename)
                    
                    if not os.path.exists(frag_path):
                        print(f"❌ Lỗi: Thiếu mảnh dữ liệu tại {frag_path}")
                        raise FileNotFoundError(f"Missing {frag_filename}")

                    with open(frag_path, "rb") as f:
                        data = f.read()
                    
                    # Tách dữ liệu: IV (12b), Tag (16b), Ciphertext còn lại
                    iv, tag, ciphertext = data[:12], data[12:28], data[28:]
                    
                    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                    decrypted_chunks.append(decrypted_data)

                # 4. Lưu file kết quả
                out_filename = "DECRYPTED_" + manifest["original_filename"]
                out_path = os.path.join(DOWNLOADS_PATH, out_filename)
                with open(out_path, "wb") as f:
                    for chunk in decrypted_chunks:
                        f.write(chunk)
                
                print(f"🎉 GIẢI MÃ THÀNH CÔNG!")
                print(f"📍 File đã khôi phục tại: {out_path}")

            except (ValueError, IndexError):
                print("❌ Lựa chọn không hợp lệ.")
            except Exception as e:
                print(f"❌ Lỗi hệ thống: {e}")

        elif choice == "3":
            files = list_files()
            if not files:
                print("📭 Cloud trống.")
            else:
                print("\n📋 File hiện có trên Cloud:")
                for f in files: print(f"  • {f}")

        elif choice == "4":
            print("👋 Đang thoát hệ thống...")
            break

if __name__ == "__main__":
    main()