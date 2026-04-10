def classify_input(strings):
    for s in strings:
        l = s.lower()
        if "ontransact" in l:
            return "binder"
        if "recvfrom" in l or "recvmsg" in l or "accept(" in l:
            return "socket"
        if "recv" in l or "accept" in l:
            return "socket"
    return None


def has_input_handler(strings):
    return any(
        "recv" in s.lower() or "read(" in s.lower() or "accept(" in s.lower()
        for s in strings
    )
