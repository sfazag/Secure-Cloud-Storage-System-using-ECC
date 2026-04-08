# file_handler.py
import os
import hashlib
import json
from config import FRAGMENT_SIZE

def split_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    fragments = []
    for i in range(0, len(data), FRAGMENT_SIZE):
        fragment = data[i:i + FRAGMENT_SIZE]
        checksum = hashlib.sha256(fragment).digest()
        fragments.append({
            "index": len(fragments),
            "data": fragment,
            "checksum": checksum.hex()
        })
    return fragments, len(data)

def merge_fragments(fragments_data, output_path):
    with open(output_path, "wb") as f:
        for data in fragments_data:
            f.write(data)