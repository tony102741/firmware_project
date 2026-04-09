import os
import sys

SUSPICIOUS_NAMES = ["su", "busybox"]


def scan_su(root_path):
    results = []

    for root, _, files in os.walk(root_path):
        for name in files:
            if name in SUSPICIOUS_NAMES:
                results.append(os.path.join(root, name))

    return results


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "rootfs"
    for path in scan_su(root):
        print(path)