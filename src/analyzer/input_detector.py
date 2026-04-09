INPUT_KEYWORDS = [
    ".json", ".xml", ".conf",
    "/data/", "/sdcard/",
    "socket", "recv", "read"
]

def detect_inputs(strings_list):
    hits = []

    for line in strings_list:
        for kw in INPUT_KEYWORDS:
            if kw in line.lower():
                hits.append(line)
                break

    return list(set(hits))