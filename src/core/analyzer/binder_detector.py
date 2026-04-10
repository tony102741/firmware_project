def has_binder(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
            return b"binder" in data or b"IBinder" in data
    except:
        return False