"""
Scan the inputs directory and append missing firmware samples to the live
corpus inventory with best-effort metadata inference from filenames.

Usage:
  python3 src/corpus_tools/corpus_sync.py
  python3 src/corpus_tools/corpus_sync.py --write
"""

import argparse
import json
import re
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from corpus_tools.corpus import load_jsonl


ZONE_SUFFIX = ":Zone.Identifier"
_PATH_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


def slugify(value):
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def path_label(value):
    value = _PATH_INVALID_CHARS.sub("-", (value or "").strip())
    value = re.sub(r"\s+", " ", value)
    return value.strip(" .-") or "UNKNOWN"


def infer_input_type(path):
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "bin":
        try:
            with path.open("rb") as fh:
                fh.seek(257)
                if fh.read(5) == b"ustar":
                    return "tar"
        except OSError:
            pass
    return suffix or "unknown"


def infer_product_class(model):
    model_upper = model.upper()
    if model_upper.startswith("XE") or model_upper.startswith("MX42") or model_upper.startswith("MX4"):
        return "mesh"
    return "router"


def infer_release_date(token):
    match = re.fullmatch(r"(\d{4})(\d{2})(\d{2})", token)
    if not match:
        return ""
    year, month, day = match.groups()
    return f"{year}-{month}-{day}"


def infer_entry(path, inputs_root="inputs"):
    name = path.name
    try:
        rel_path = path.relative_to(inputs_root)
    except Exception:
        rel_path = Path(path.name)

    patterns = [
        (
            re.compile(r"^(A3002RU)-(?P<version>V.+)\.(?P<ext>zip|rar)$", re.I),
            lambda m: {
                "vendor": "TOTOLINK",
                "model": m.group(1),
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"B(\d{8})", m.group("version")).group(1)
                )
                if re.search(r"B(\d{8})", m.group("version"))
                else "",
                "suspected_stack": ["boa", "boafrm"],
                "arch": "mips",
                "notes": "Metadata inferred from filename pattern. Reuse the same stack assumptions as the other A3002RU samples until verified.",
            },
        ),
        (
            re.compile(
                r"^TOTOLINK-PWBATNA-(?P<model>A3002RU)-Hh-(?P<version>V.+)\.(?P<ext>web)$",
                re.I,
            ),
            lambda m: {
                "vendor": "TOTOLINK",
                "model": m.group("model"),
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"B(\d{8})", m.group("version")).group(1)
                )
                if re.search(r"B(\d{8})", m.group("version"))
                else "",
                "suspected_stack": ["boa", "boafrm"],
                "arch": "mips",
                "notes": "Metadata inferred from filename pattern. Standalone TOTOLINK .web firmware aligned to the existing A3002RU collection.",
            },
        ),
        (
            re.compile(
                r"^Archer (?P<model>C80|AX23)\(US\)_(?P<version>.+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "TP-Link",
                "model": f"Archer {m.group('model').upper()}",
                "version": m.group("version"),
                "release_date": infer_release_date(
                    f"20{re.search(r'(\d{6})$', m.group('version')).group(1)[:2]}{re.search(r'(\d{6})$', m.group('version')).group(1)[2:]}"
                )
                if re.search(r"(\d{6})$", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Region tag kept implicit in the filename and can be normalized later if needed.",
            },
        ),
        (
            re.compile(
                r"^TOTOLINK_C8380R_X6000R_.*_(?P<version>V.+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "TOTOLINK",
                "model": "X6000R",
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"B(\d{8})", m.group("version")).group(1)
                )
                if re.search(r"B(\d{8})", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. The vendor bundle mentions both C8380R and X6000R; corpus normalization currently tracks this under X6000R.",
            },
        ),
        (
            re.compile(r"^(X6000R)_(?P<version>V.+)\.(?P<ext>rar)$", re.I),
            lambda m: {
                "vendor": "TOTOLINK",
                "model": m.group(1),
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"B(\d{8})", m.group("version")).group(1)
                )
                if re.search(r"B(\d{8})", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern.",
            },
        ),
        (
            re.compile(r"^(V\d+\.\d+\.\w+\.\d+_B\d{8}_ALL)\.(?P<ext>rar)$", re.I),
            lambda m: {
                "vendor": "TOTOLINK",
                "model": "X6000R",
                "version": m.group(1),
                "release_date": infer_release_date(
                    re.search(r"B(\d{8})", m.group(1)).group(1)
                )
                if re.search(r"B(\d{8})", m.group(1))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Model inferred as X6000R from the surrounding local collection. Verify against the original download source before using this as a cleaned benchmark row.",
            },
        ),
        (
            re.compile(
                r"^(WR1300V4)-(?P<version>R\d+-\d+\.\d+\.\d+-\d{8}-\d+)-flash\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Cudy",
                "model": "WR1300 V4",
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"-(\d{8})-", m.group("version")).group(1)
                )
                if re.search(r"-(\d{8})-", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Vendor should be verified against the original download source if you later publish the corpus.",
            },
        ),
        (
            re.compile(
                r"^(WR3000E)-(?P<version>R\d+-\d+\.\d+\.\d+-\d{8}-\d+)-sysupgrade\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Cudy",
                "model": m.group(1),
                "version": m.group("version"),
                "release_date": infer_release_date(
                    re.search(r"-(\d{8})-", m.group("version")).group(1)
                )
                if re.search(r"-(\d{8})-", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Vendor should be verified against the original download source if you later publish the corpus.",
            },
        ),
        (
            re.compile(
                r"^(XE75_XE5300_WE10800)_(?P<version>.+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "TP-Link",
                "model": "XE75 / XE5300 / WE10800",
                "version": m.group("version").replace("_", " "),
                "release_date": infer_release_date(
                    re.search(r"(\d{8})", m.group("version")).group(1)
                )
                if re.search(r"(\d{8})", m.group("version"))
                else "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Product family aliases are kept grouped until you decide whether to split them by retail region.",
            },
        ),
        (
            re.compile(
                r"^(?P<model>MR60X|MR70X)_V(?P<hw>\d+(?:\.\d+)?)_(?P<version>\d+\.\d+\.\d+)_Build_(?P<build>\d+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "MERCUSYS",
                "model": m.group("model").upper(),
                "version": f"V{m.group('hw')}_{m.group('version')}_Build_{m.group('build')}",
                "release_date": infer_release_date(m.group("build")[:8]),
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Build timestamp is preserved as part of the normalized version string.",
            },
        ),
        (
            re.compile(
                r"^(?P<model>MR90X)\((?P<region>[A-Z]+)\)_V(?P<hw>\d+(?:\.\d+)?)_(?P<build>\d+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "MERCUSYS",
                "model": f"{m.group('model').upper()} ({m.group('region').upper()})",
                "version": f"V{m.group('hw')}_{m.group('build')}",
                "release_date": "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Region tag is kept in the model name because the local filename encodes it explicitly.",
            },
        ),
        (
            re.compile(
                r"^(?P<region>[A-Z]{2})_(?P<model>AX12Pro)V(?P<hw>\d+\.\d+)\w*_V(?P<version>\d+\.\d+\.\d+\.\d+)_(?P<build>[A-Z0-9]+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Tenda",
                "model": m.group("model"),
                "version": f"V{m.group('hw')}_{m.group('version')}_{m.group('build')}",
                "release_date": "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Tenda regional prefix is omitted from the model and retained only in the original filename.",
            },
        ),
        (
            re.compile(
                r"^(?P<region>[A-Z]{2})_(?P<model>TX2Pro)V(?P<hw>\d+\.\d+)\w*_V(?P<version>\d+\.\d+\.\d+\.\d+)_multi_(?P<build>[A-Z0-9]+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Tenda",
                "model": m.group("model"),
                "version": f"V{m.group('hw')}_{m.group('version')}_multi_{m.group('build')}",
                "release_date": "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Multi-region bundle marker is kept in the version string.",
            },
        ),
        (
            re.compile(
                r"^(?P<model>mt3000)-(?P<version>\d+\.\d+\.\d+)-(?P<build>\d+)-(?P<stamp>\d+)\.(?P<ext>tar)$",
                re.I,
            ),
            lambda m: {
                "vendor": "GL.iNet",
                "model": f"GL-{m.group('model').upper()}",
                "version": m.group("version"),
                "release_date": "",
                "suspected_stack": ["openwrt", "uhttpd", "rpcd"],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. GL.iNet sysupgrade tar archive with nested kernel/root payloads.",
            },
        ),
        (
            re.compile(
                r"^(?P<model>mt6000|x3000)-(?P<version>\d+\.\d+\.\d+)_(?P<channel>release\d+)-(?P<build>\d+)-(?P<patch>\d+)-(?P<stamp>\d+)\.(?P<ext>bin)$",
                re.I,
            ),
            lambda m: {
                "vendor": "GL.iNet",
                "model": f"GL-{m.group('model').upper()}",
                "version": f"{m.group('version')}-{m.group('channel')}-{m.group('build')}-{m.group('patch')}",
                "release_date": "",
                "suspected_stack": ["openwrt", "uhttpd", "rpcd"],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Local .bin name is a GL.iNet sysupgrade tar archive in disguise.",
            },
        ),
        (
            re.compile(
                r"^(ax(?P<model>2004m|3000m))_ml_(?P<version>\d+_\d+)\.(?P<ext>bin)$",
                re.I,
            ),
            lambda m: {
                "vendor": "ipTIME",
                "model": f"AX{m.group('model').upper()}",
                "version": m.group("version").replace("_", "."),
                "release_date": "",
                "suspected_stack": [],
                "arch": "",
                "notes": "Metadata inferred from filename pattern. Release date is not embedded in the local filename.",
            },
        ),
        (
            re.compile(
                r"^FW_(?P<model>RT_AX58U)_(?P<version>\d+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "ASUS",
                "model": m.group("model").replace("_", "-"),
                "version": {
                    "300438825127": "3.0.0.4_388_25127",
                    "300438825155": "3.0.0.4_388_25155",
                    "300438825277": "3.0.0.4_388_25277",
                }.get(m.group("version"), m.group("version")),
                "release_date": "",
                "suspected_stack": ["boa", "micro_httpd", "ubifs"],
                "arch": "",
                "notes": "Metadata inferred from ASUS download filename pattern. Inner archive member carries the firmware payload.",
            },
        ),
        (
            re.compile(
                r"^FW_(?P<model>MX4200|MX42SH)_(?P<version>\d+\.\d+\.\d+\.\d+)_prod\.(?P<ext>img)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Linksys",
                "model": m.group("model").upper(),
                "version": m.group("version"),
                "release_date": "",
                "suspected_stack": ["boa", "qcom", "squashfs"],
                "arch": "",
                "notes": "Metadata inferred from Linksys signed IMG filename pattern. Product class should be treated as mesh for MX-series devices.",
            },
        ),
        (
            re.compile(
                r"^(?P<model>RAX50)-V(?P<version>\d+\.\d+\.\d+\.\d+)_(?P<build>\d+\.\d+\.\d+)\.(?P<ext>zip)$",
                re.I,
            ),
            lambda m: {
                "vendor": "NETGEAR",
                "model": m.group("model").upper(),
                "version": f"V{m.group('version')}_{m.group('build')}",
                "release_date": "",
                "suspected_stack": ["micro_httpd", "ubifs", "broadcom"],
                "arch": "",
                "notes": "Metadata inferred from NETGEAR firmware ZIP pattern. Archive contains a .chk payload plus release notes.",
            },
        ),
        (
            re.compile(
                r"^SRM_(?P<model>RT6600ax)_(?P<build>\d+)\.(?P<ext>pat)$",
                re.I,
            ),
            lambda m: {
                "vendor": "Synology",
                "model": m.group("model"),
                "version": m.group("build"),
                "release_date": "",
                "suspected_stack": ["synology", "package-firmware", "tar"],
                "arch": "",
                "notes": "Metadata inferred from Synology SRM PAT package naming. PAT is a tar-like firmware bundle rather than a plain router image.",
            },
        ),
    ]

    for pattern, builder in patterns:
        match = pattern.match(name)
        if not match:
            continue
        inferred = builder(match)
        version = inferred["version"]
        model = inferred["model"]
        vendor = inferred["vendor"]
        return {
            "corpus_id": slugify(f"{vendor}-{model}-{version}"),
            "vendor": vendor,
            "model": model,
            "version": version,
            "release_date": inferred["release_date"],
            "local_filename": name,
            "local_path": str(Path(inputs_root) / rel_path).replace("\\", "/"),
            "source_url": "",
            "source_page": "",
            "input_type": infer_input_type(path),
            "product_class": infer_product_class(model),
            "web_ui_expected": True,
            "extraction_status": "PENDING",
            "analysis_status": "PENDING",
            "run_id": "",
            "web_surface_detected": None,
            "suspected_stack": inferred["suspected_stack"],
            "arch": inferred["arch"],
            "notes": inferred["notes"],
        }

    return {
        "corpus_id": slugify(path.stem),
        "vendor": "UNKNOWN",
        "model": path.stem,
        "version": path.stem,
        "release_date": "",
        "local_filename": name,
        "local_path": str(Path(inputs_root) / rel_path).replace("\\", "/"),
        "source_url": "",
        "source_page": "",
        "input_type": infer_input_type(path),
        "product_class": "router",
        "web_ui_expected": True,
        "extraction_status": "PENDING",
        "analysis_status": "PENDING",
        "run_id": "",
        "web_surface_detected": None,
        "suspected_stack": [],
        "arch": "",
        "notes": "Filename did not match a known pattern. Fill vendor/model/version manually before using this row in a benchmark.",
    }


def iter_input_files(inputs_dir):
    root = Path(inputs_dir)
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name.endswith(ZONE_SUFFIX):
            continue
        yield path


def find_missing_entries(inputs_dir, corpus_path):
    corpus_entries, errors = load_jsonl(corpus_path)
    if errors:
        raise ValueError("\n".join(errors))

    known_paths = {
        str(Path(entry.get("local_path", "")).as_posix())
        for entry in corpus_entries
        if entry.get("local_path")
    }
    known_names = {
        entry["local_filename"]
        for entry in corpus_entries
        if entry.get("local_filename")
    }
    missing = []
    root = Path(inputs_dir)
    for path in iter_input_files(root):
        rel_local_path = str((root / path.relative_to(root))).replace("\\", "/")
        if rel_local_path in known_paths or path.name in known_names:
            continue
        missing.append(infer_entry(path, inputs_root=root))
    return missing


def append_entries(corpus_path, entries):
    with open(corpus_path, "a", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, ensure_ascii=False))
            fh.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scan inputs/ and append missing firmware samples to the live corpus."
    )
    parser.add_argument(
        "--inputs",
        default="inputs",
        help="Directory containing collected firmware files.",
    )
    parser.add_argument(
        "--corpus",
        default="research/corpus/firmware_corpus.jsonl",
        help="Path to the live corpus JSONL file.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Append inferred entries to the corpus file. Without this flag, print only.",
    )
    args = parser.parse_args()

    entries = find_missing_entries(args.inputs, args.corpus)
    print(f"missing_entries: {len(entries)}")
    for entry in entries:
        print(json.dumps(entry, ensure_ascii=False))

    if args.write and entries:
        append_entries(args.corpus, entries)


if __name__ == "__main__":
    main()
