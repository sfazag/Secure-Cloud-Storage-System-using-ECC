# storage_simulator.py
import os
import json
from config import SIMULATED_CLOUD_PATH

# Lấy đường dẫn gốc của dự án để đảm bảo lưu đúng chỗ
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLOUD_ROOT = os.path.join(BASE_DIR, SIMULATED_CLOUD_PATH)
FRAGMENTS_DIR = os.path.join(CLOUD_ROOT, "fragments")
MANIFESTS_DIR = os.path.join(CLOUD_ROOT, "manifests")

# Tạo thư mục nếu chưa có
os.makedirs(FRAGMENTS_DIR, exist_ok=True)
os.makedirs(MANIFESTS_DIR, exist_ok=True)

def save_fragment(file_id, index, data):
    filename = f"{file_id}_frag_{index:03d}.enc"
    path = os.path.join(FRAGMENTS_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    return path

def save_manifest(file_id, manifest):
    filename = f"{file_id}_manifest.json"
    path = os.path.join(MANIFESTS_DIR, filename)
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    return path

def load_manifest(file_id):
    path = os.path.join(MANIFESTS_DIR, f"{file_id}_manifest.json")
    with open(path, "r") as f:
        return json.load(f)

def list_files():
    if not os.path.exists(MANIFESTS_DIR):
        return []
    manifests = os.listdir(MANIFESTS_DIR)
    return sorted([m.replace("_manifest.json", "") for m in manifests if m.endswith(".json")])