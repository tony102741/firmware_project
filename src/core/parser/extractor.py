import subprocess

def extract_payload(payload_path):
    subprocess.run([
        "python3",
        "payload_dumper/payload_dumper/payload_dumper.py",
        payload_path
    ])