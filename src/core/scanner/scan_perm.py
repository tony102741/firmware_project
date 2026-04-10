import os
import stat
import sys


def scan_world_writable(root_path):
    results = []

    for root, _, files in os.walk(root_path):
        for name in files:
            full_path = os.path.join(root, name)
            try:
                st = os.stat(full_path)
                if st.st_mode & stat.S_IWOTH:
                    results.append(full_path)
            except:
                pass

    return results


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "rootfs"
    for path in scan_world_writable(root):
        print(path)