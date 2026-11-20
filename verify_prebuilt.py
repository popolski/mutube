#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "capstone>=5.0.6",
#     "lief>=0.17.3",
# ]
# ///
"""Check whether a prebuilt MuTube IPA is exactly what this checkout's patcher.py produces.

Run from a directory holding patcher.py + inject.js of the MuTube version to compare against:
    uv run verify_prebuilt.py path/to/prebuilt.ipa

Method: undo the patch (restore the original instructions the patcher expects and zero the
__TEXT header padding), run patcher.patch_binary() on that, and diff the result with the
prebuilt binary byte for byte (code signature excluded). Zero differences means the binary
contains nothing beyond the official MuTube patch. Also reports extra files and dylibs.
"""
import re
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

import capstone
import lief

sys.path.insert(0, str(Path.cwd()))
import patcher  # noqa: E402

MD = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)


def enc(mnemonic, ops, pc):
    """Encode the few instruction forms the patcher expects to find."""
    m = re.fullmatch(r"w(\d+), \[x(\d+), #0x([0-9a-f]+)\]", ops)
    if mnemonic == "ldrb" and m:
        rt, rn, imm = int(m[1]), int(m[2]), int(m[3], 16)
        return 0x39400000 | imm << 10 | rn << 5 | rt
    m = re.fullmatch(r"x(\d+), x(\d+)", ops)
    if mnemonic == "mov" and m:
        return 0xAA0003E0 | int(m[2]) << 16 | int(m[1])
    m = re.fullmatch(r"w(\d+), #0x([0-9a-f]+)", ops)
    if mnemonic == "cbz" and m:
        return 0x34000000 | (((int(m[2], 16) - pc) >> 2) & 0x7FFFF) << 5 | int(m[1])
    m = re.fullmatch(r"#0x([0-9a-f]+)", ops)
    if mnemonic == "b" and m:
        return 0x14000000 | (((int(m[1], 16) - pc) >> 2) & 0x3FFFFFF)
    raise ValueError(f"cannot encode {mnemonic} {ops}")


def checked_enc(mnemonic, ops, pc):
    word = enc(mnemonic, ops, pc)
    insn = next(MD.disasm(struct.pack("<I", word), pc))
    assert (insn.mnemonic, insn.op_str) == (mnemonic, ops), (insn.mnemonic, insn.op_str, mnemonic, ops)
    return word


def unpatch(data):
    info = patcher.parse_macho_info(data)
    for p in getattr(patcher, "PATCHES", []) + getattr(patcher, "COBALT_HOOKS", []):
        site_va, site_off, _, insn = patcher.resolve_patch_site(data, info, p["entry_va"])
        print(f"  {p['name']}: site {hex(site_va)} has '{insn.mnemonic} {insn.op_str}'")
        data[site_off:site_off + 4] = struct.pack("<I", checked_enc(*p["expect"], site_va))
    for p in getattr(patcher, "COBALT_HDR_PATCHES", []):
        off = patcher.va_to_off(info, p["va"])
        data[off:off + 4] = struct.pack("<I", checked_enc(*p["expect"], p["va"]))
    data[info["header_end"]:info["text_off"]] = bytes(info["text_off"] - info["header_end"])


def signature_range(data):
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "b"
        f.write_bytes(data)
        b = lief.parse(str(f))
        libs = [l.name for l in b.libraries]
        sig = next((c for c in b.commands if type(c).__name__ == "CodeSignature"), None)
    return (sig.data_offset, sig.data_offset + sig.data_size) if sig else (len(data), len(data)), libs


def diff_ranges(a, b, skip):
    out, i, n = [], 0, min(len(a), len(b))
    while i < n:
        if skip[0] <= i < skip[1]:
            i = skip[1]
            continue
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j] and not (skip[0] <= j < skip[1]):
                j += 1
            out.append((i, j))
            i = j
        else:
            i += 1
    return out


def main(ipa):
    with zipfile.ZipFile(ipa) as z:
        names = z.namelist()
        bin_name = next(n for n in names if n.endswith("/YouTubeUnstable"))
        prebuilt = bytearray(z.read(bin_name))

    print("Files that are code (dylib/framework/appex/script/js):")
    for n in names:
        if re.search(r"\.(dylib|appex|js|sh|py)$|\.framework/[^/]+$", n) and not n.endswith("/"):
            print("  ", n)

    sig, libs = signature_range(prebuilt)
    print("Linked libraries not in /usr/lib or /System:")
    for l in libs:
        if not l.startswith(("/usr/lib/", "/System/")):
            print("  ", l)

    info = patcher.parse_macho_info(prebuilt)
    pad = bytes(prebuilt[info["header_end"]:info["text_off"]])
    print("URLs in injected payload:", sorted(set(re.findall(rb"https?://[\x21-\x7e]+", pad))))

    rebuilt = bytearray(prebuilt)
    unpatch(rebuilt)
    patcher.patch_binary(rebuilt)

    if len(rebuilt) != len(prebuilt):
        print(f"RESULT: MISMATCH (size {len(prebuilt)} vs rebuilt {len(rebuilt)})")
        return 1
    diffs = diff_ranges(prebuilt, rebuilt, sig)
    if not diffs:
        print("RESULT: IDENTICAL to this MuTube version (code signature excluded)")
        return 0
    print(f"RESULT: MISMATCH, {len(diffs)} differing ranges (first 20):")
    for s, e in diffs[:20]:
        print(f"  file offset {hex(s)}-{hex(e)} ({e - s} bytes) prebuilt={bytes(prebuilt[s:min(e, s + 32)]).hex()}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
