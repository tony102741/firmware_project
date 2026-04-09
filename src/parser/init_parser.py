import os

def parse_init_services(root_path):
    services = []

    for root, _, files in os.walk(root_path):
        for name in files:
            if name.endswith(".rc"):
                full_path = os.path.join(root, name)

                source = "vendor" if "/vendor/" in full_path else "system"

                try:
                    with open(full_path, "r", errors="ignore") as f:
                        current = None

                        for line in f:
                            line = line.strip()

                            if not line or line.startswith("#"):
                                continue

                            if line.startswith("service"):
                                parts = line.split()
                                if len(parts) >= 3:
                                    current = {
                                        "name": parts[1],
                                        "exec": parts[2],
                                        "user": None,
                                        "source": source,
                                        "socket": []
                                    }
                                    services.append(current)

                            elif current:
                                if line.startswith("user"):
                                    current["user"] = line.split()[1]

                                elif line.startswith("socket"):
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        current["socket"].append({
                                            "name": parts[1],
                                            "perm": parts[3]
                                        })

                except:
                    pass

    return services