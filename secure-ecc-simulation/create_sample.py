# create_sample.py
import os

def create_1mb_file(filename="test_1MB.txt"):
    target_size = 1024 * 1024  # 1 MB
    content = "Hệ thống bảo mật ECC và AES - Dự án mô phỏng Secure Cloud Storage. "
    
    # Lặp lại nội dung cho đến khi đạt đủ 1MB
    with open(os.path.join("uploads", filename), "w", encoding="utf-8") as f:
        while os.path.getsize(os.path.join("uploads", filename)) < target_size:
            f.write(content)
            
    print(f"✅ Đã tạo file thực tế tại: uploads/{filename} (Size: {os.path.getsize(os.path.join('uploads', filename))} bytes)")

if __name__ == "__main__":
    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    create_1mb_file()