# main.py
import os
import json
import time
import psutil
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from crypto import ECCSecureStorage
from file_handler import split_file
from storage_simulator import save_fragment, save_manifest, load_manifest, list_files
from config import UPLOADS_PATH, DOWNLOADS_PATH, SIMULATED_CLOUD_PATH

# ====================== CẤU HÌNH ĐƯỜNG DẪN ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOADS_PATH = os.path.join(BASE_DIR, "uploads")
DOWNLOADS_PATH = os.path.join(BASE_DIR, "downloads")
CLOUD_FRAGMENTS_DIR = os.path.join(BASE_DIR, SIMULATED_CLOUD_PATH, "fragments")

os.makedirs(UPLOADS_PATH, exist_ok=True)
os.makedirs(DOWNLOADS_PATH, exist_ok=True)

ecc = ECCSecureStorage()

def get_memory_usage():
    """Lấy lượng RAM hiện tại chương trình đang sử dụng (MB)"""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def main():
    print("🔑 Đang kiểm tra / tạo khóa ECC...")
    ecc.generate_keys()
    
    print("\n" + "="*75)
    print("🚀 HỆ THỐNG MÔ PHỎNG SECURE CLOUD STORAGE (PERFORMANCE MONITOR)")
    print("="*75)

    while True:
        print("\n1. Upload file (Encryption + Benchmarking)")
        print("2. Download file (Decryption + Benchmarking)")
        print("3. Xem danh sách file trên Cloud")
        print("4. Thoát")
        
        choice = input("\nChọn chức năng (1-4): ").strip()

        # ==================== CHỨC NĂNG 1: UPLOAD ====================
        if choice == "1":
            filename = input("Nhập tên file trong thư mục uploads/: ").strip()
            filepath = os.path.join(UPLOADS_PATH, filename)

            if not os.path.exists(filepath):
                print(f"❌ Không tìm thấy file tại: {filepath}")
                continue

            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            file_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
            
            # --- BẮT ĐẦU ĐO HIỆU SUẤT UPLOAD ---
            start_time = time.perf_counter()
            mem_before = get_memory_usage()

            # 1. ECC Wrap AES Key
            aes_key = os.urandom(32)
            wrapped = ecc.ecies_encrypt_aes_key(aes_key)
            wrapped_serializable = {k: v.hex() for k, v in wrapped.items()}

            # 2. Fragmentation & Encryption
            fragments, original_size = split_file(filepath)
            manifest = {
                "file_id": file_id, "original_filename": filename,
                "original_size": original_size, "fragment_count": len(fragments),
                "wrapped_aes": wrapped_serializable, "fragments": []
            }

            for frag in fragments:
                iv = os.urandom(12)
                cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(frag["data"]) + encryptor.finalize()
                encrypted_data = iv + encryptor.tag + ciphertext
                save_fragment(file_id, frag["index"], encrypted_data)
                manifest["fragments"].append({"index": frag["index"], "checksum": frag["checksum"]})

            # 3. ECDSA Sign
            manifest_json_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
            signature = ecc.sign_manifest(manifest_json_bytes)
            manifest["signature"] = signature.hex()
            save_manifest(file_id, manifest)

            end_time = time.perf_counter()
            mem_after = get_memory_usage()
            # --- KẾT THÚC ĐO ---

            duration = end_time - start_time
            throughput = file_size_mb / duration if duration > 0 else 0

            print(f"\n📊 --- KẾT QUẢ HIỆU SUẤT UPLOAD ---")
            print(f"⏱  Thời gian thực thi: {duration:.4f} giây")
            print(f"🚀 Thông lượng (Throughput): {throughput:.2f} MB/s")
            print(f"🧠 RAM sử dụng: {mem_after:.2f} MB")
            print(f"✅ UPLOAD THÀNH CÔNG! File ID: {file_id}")

        # ==================== CHỨC NĂNG 2: DOWNLOAD ====================
        elif choice == "2":
            files = list_files()
            if not files:
                print("📭 Cloud trống."); continue
            
            for idx, f in enumerate(files): print(f"  {idx+1}. {f}")
            
            try:
                f_choice = input("\nChọn số thứ tự file: ").strip()
                selected_id = files[int(f_choice)-1]
                
                # --- BẮT ĐẦU ĐO HIỆU SUẤT DOWNLOAD ---
                start_time = time.perf_counter()
                
                manifest = load_manifest(selected_id)
                sig_hex = manifest.pop("signature")
                manifest_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
                
                if not ecc.verify_signature(manifest_bytes, bytes.fromhex(sig_hex)):
                    print("❌ Signature mismatch!"); continue

                wrapped_bytes = {k: bytes.fromhex(v) for k, v in manifest["wrapped_aes"].items()}
                aes_key = ecc.ecies_decrypt_aes_key(wrapped_bytes)

                decrypted_chunks = []
                for frag_info in manifest["fragments"]:
                    frag_path = os.path.join(CLOUD_FRAGMENTS_DIR, f"{selected_id}_frag_{frag_info['index']:03d}.enc")
                    with open(frag_path, "rb") as f:
                        data = f.read()
                    iv, tag, ciphertext = data[:12], data[12:28], data[28:]
                    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
                    decrypted_chunks.append(cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize())

                out_path = os.path.join(DOWNLOADS_PATH, "RESTORED_" + manifest["original_filename"])
                with open(out_path, "wb") as f:
                    for chunk in decrypted_chunks: f.write(chunk)

                end_time = time.perf_counter()
                # --- KẾT THÚC ĐO ---

                duration = end_time - start_time
                file_size_mb = os.path.getsize(out_path) / (1024 * 1024)
                throughput = file_size_mb / duration if duration > 0 else 0

                print(f"\n📊 --- KẾT QUẢ HIỆU SUẤT DOWNLOAD ---")
                print(f"⏱  Thời gian thực thi: {duration:.4f} giây")
                print(f"🚀 Thông lượng (Throughput): {throughput:.2f} MB/s")
                print(f"🎉 GIẢI MÃ THÀNH CÔNG tại: {out_path}")

            except Exception as e:
                print(f"❌ Lỗi: {e}")

        elif choice == "3":
            files = list_files()
            for f in files: print(f"  • {f}")

        elif choice == "4":
            break

if __name__ == "__main__":
    main()
