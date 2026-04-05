# main.py
import os
import json
import time
import psutil
import traceback # Thêm thư viện để in lỗi chi tiết
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
    try:
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)
    except:
        return 0.0

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

            try:
                file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                file_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + filename
                
                # --- BẮT ĐẦU ĐO HIỆU SUẤT UPLOAD ---
                start_time = time.perf_counter()

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
                    
                    # Cấu trúc: IV (12) + TAG (16) + Dữ liệu
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
                
                duration = end_time - start_time
                throughput = file_size_mb / duration if duration > 0 else 0

                print(f"\n📊 --- KẾT QUẢ HIỆU SUẤT UPLOAD ---")
                print(f"⏱  Thời gian thực thi: {duration:.4f} giây")
                print(f"🚀 Thông lượng (Throughput): {throughput:.2f} MB/s")
                print(f"🧠 RAM sử dụng: {mem_after:.2f} MB")
                print(f"✅ UPLOAD THÀNH CÔNG! File ID: {file_id}")
            except Exception as e:
                print(f"❌ Lỗi khi Upload: {e}")
                traceback.print_exc()

        # ==================== CHỨC NĂNG 2: DOWNLOAD ====================
        elif choice == "2":
            files = list_files()
            if not files:
                print("📭 Cloud trống."); continue
            
            print("\n📋 Danh sách file khả dụng:")
            for idx, f in enumerate(files): print(f"  {idx+1}. {f}")
            
            try:
                f_choice = input("\nChọn số thứ tự file: ").strip()
                selected_id = files[int(f_choice)-1]
                
                # --- BẮT ĐẦU ĐO HIỆU SUẤT DOWNLOAD ---
                start_time = time.perf_counter()
                
                manifest = load_manifest(selected_id)
                sig_hex = manifest.pop("signature")
                manifest_bytes = json.dumps(manifest, sort_keys=True).encode('utf-8')
                
                # Kiểm tra chữ ký Manifest
                if not ecc.verify_signature(manifest_bytes, bytes.fromhex(sig_hex)):
                    print("❌ CẢNH BÁO: Manifest đã bị thay đổi trái phép (Signature mismatch)!"); continue

                # Giải mã khóa AES
                wrapped_bytes = {k: bytes.fromhex(v) for k, v in manifest["wrapped_aes"].items()}
                aes_key = ecc.ecies_decrypt_aes_key(wrapped_bytes)

                decrypted_chunks = []
                for frag_info in manifest["fragments"]:
                    frag_filename = f"{selected_id}_frag_{frag_info['index']:03d}.enc"
                    frag_path = os.path.join(CLOUD_FRAGMENTS_DIR, frag_filename)
                    
                    with open(frag_path, "rb") as f:
                        data = f.read()
                    
                    # Bóc tách cấu trúc dữ liệu
                    iv, tag, ciphertext = data[:12], data[12:28], data[28:]
                    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
                    decryptor = cipher.decryptor()
                    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                    decrypted_chunks.append(decrypted_data)

                # Ghi file đã khôi phục
                out_filename = "RESTORED_" + manifest["original_filename"]
                out_path = os.path.join(DOWNLOADS_PATH, out_filename)
                with open(out_path, "wb") as f:
                    for chunk in decrypted_chunks: f.write(chunk)

                end_time = time.perf_counter()
                
                # Tính toán thông số
                duration = end_time - start_time
                file_size_mb = os.path.getsize(out_path) / (1024 * 1024)
                throughput = file_size_mb / duration if duration > 0 else 0

                print(f"\n📊 --- KẾT QUẢ HIỆU SUẤT DOWNLOAD ---")
                print(f"⏱  Thời gian thực thi: {duration:.4f} giây")
                print(f"🚀 Thông lượng (Throughput): {throughput:.2f} MB/s")
                print(f"🎉 GIẢI MÃ THÀNH CÔNG tại: {out_path}")

            except Exception as e:
                print(f"\n❌ Lỗi chi tiết tại bước Download:")
                print("-" * 30)
                traceback.print_exc() # In ra lỗi cụ thể ở dòng nào
                print("-" * 30)

        elif choice == "3":
            files = list_files()
            if not files: print("📭 Cloud trống.")
            for f in files: print(f"  • {f}")

        elif choice == "4":
            print("👋 Tạm biệt!")
            break

if __name__ == "__main__":
    main()
