#!/usr/bin/env python3
"""
Patch selected JUCE 8 Windows VST3 binaries to avoid Direct2D UI paths under Wine.

This is intentionally conservative:
- creates backups before writing
- handles read-only files by restoring their original mode
- treats ambiguous byte signatures as errors
- distinguishes confirmed, testing, and experimental recipes
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import re
import os
import shutil
import stat
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Callable


HOME = Path.home()
DEFAULT_BACKUP_ROOT = HOME / ".local/share/plugin-binary-backups"


@dataclasses.dataclass(frozen=True)
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    raw_size: int


class PEImage:
    def __init__(self, data: bytes):
        pe = data.find(b"PE\0\0")
        if pe < 0:
            raise ValueError("not a PE image")

        coff = pe + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]

        if magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        elif magic == 0x10B:
            self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        else:
            raise ValueError(f"unknown PE optional header magic 0x{magic:x}")

        sec_off = opt + opt_size
        sections: list[Section] = []
        for i in range(num_sections):
            off = sec_off + i * 40
            name = data[off : off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            vsize, va, raw_size, raw = struct.unpack_from("<IIII", data, off + 8)
            sections.append(Section(name, va, vsize, raw, raw_size))

        self.sections = sections

    def raw_to_va(self, raw: int) -> int | None:
        for s in self.sections:
            if s.raw <= raw < s.raw + s.raw_size:
                return self.image_base + s.va + (raw - s.raw)
        return None

    def va_to_raw(self, va: int) -> int | None:
        rva = va - self.image_base
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.raw_size):
                return s.raw + (rva - s.va)
        return None


@dataclasses.dataclass
class PatchOutcome:
    description: str
    status: str
    detail: str = ""


@dataclasses.dataclass
class PluginRecipe:
    slug: str
    display_name: str
    status: str
    default_path: Path
    patchers: list[Callable[[bytearray, PEImage], PatchOutcome]]


def parse_pattern(pattern: str) -> list[int | None]:
    out: list[int | None] = []
    for token in pattern.split():
        if token in {"?", "??"}:
            out.append(None)
        else:
            out.append(int(token, 16))
    return out


def find_pattern(data: bytes | bytearray, pattern: str) -> list[int]:
    parts = parse_pattern(pattern)
    plen = len(parts)
    if plen == 0 or len(data) < plen:
        return []

    anchor_index = next((i for i, part in enumerate(parts) if part is not None), None)
    if anchor_index is None:
        return list(range(0, len(data) - plen + 1))

    anchor = parts[anchor_index]
    assert anchor is not None

    matches: list[int] = []
    start = 0
    while True:
        anchor_pos = data.find(bytes([anchor]), start)
        if anchor_pos < 0:
            return matches

        candidate = anchor_pos - anchor_index
        start = anchor_pos + 1
        if candidate < 0 or candidate + plen > len(data):
            continue

        for j, expected in enumerate(parts):
            if expected is not None and data[candidate + j] != expected:
                break
        else:
            matches.append(candidate)


def find_c_string(data: bytes | bytearray, text: str) -> list[int]:
    needle = text.encode("ascii") + b"\0"
    out: list[int] = []
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + 1


def qword(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def patch_pattern_bytes(
    data: bytearray,
    description: str,
    old_pattern: str,
    already_pattern: str,
    write_offset: int,
    old_bytes: bytes,
    new_bytes: bytes,
) -> PatchOutcome:
    already = find_pattern(data, already_pattern)
    old = find_pattern(data, old_pattern)

    if already and not old:
        return PatchOutcome(description, "already", f"{len(already)} already-patched match(es)")

    if len(old) == 0:
        return PatchOutcome(description, "missing", "signature not found")

    if len(old) > 1:
        return PatchOutcome(description, "error", f"ambiguous signature: {len(old)} matches")

    off = old[0] + write_offset
    current = bytes(data[off : off + len(old_bytes)])
    if current != old_bytes:
        return PatchOutcome(description, "error", f"unexpected bytes at raw 0x{off:x}: {current.hex(' ')}")

    data[off : off + len(new_bytes)] = new_bytes
    return PatchOutcome(description, "patched", f"raw 0x{off:x}")


def patch_create_new_peer_engine_zero(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "Component::createNewPeer engine argument 1 -> 0",
        "48 89 44 24 58 c7 44 24 28 01 00 00 00",
        "48 89 44 24 58 c7 44 24 28 00 00 00 00",
        9,
        bytes.fromhex("01 00 00 00"),
        bytes.fromhex("00 00 00 00"),
    )


def patch_create_new_peer_engine_zero_temperance(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "Temperance Pro createNewPeer engine argument 1 -> 0",
        "c7 44 24 28 01 00 00 00 c6 44 24 20 00 48 89 45 f8",
        "c7 44 24 28 00 00 00 00 c6 44 24 20 00 48 89 45 f8",
        4,
        bytes.fromhex("01 00 00 00"),
        bytes.fromhex("00 00 00 00"),
    )


def patch_create_new_peer_engine_zero_kick(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "Kick Ninja createNewPeer engine argument 1 -> 0",
        "48 89 44 24 58 48 85 c0 74 2f c7 44 24 28 01 00 00 00 c6 44 24 20 00",
        "48 89 44 24 58 48 85 c0 74 2f c7 44 24 28 00 00 00 00 c6 44 24 20 00",
        14,
        bytes.fromhex("01 00 00 00"),
        bytes.fromhex("00 00 00 00"),
    )


def patch_native_image_r14_null(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "NativeImageType factory fallback r14 -> null",
        "4c 8b 70 38 4d 85 f6 0f 84",
        "4d 33 f6 90 4d 85 f6 0f 84",
        0,
        bytes.fromhex("4c 8b 70 38"),
        bytes.fromhex("4d 33 f6 90"),
    )


def patch_native_image_rsi_null(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "NativeImageType factory fallback rsi -> null",
        "48 8b 70 38 48 85 f6 0f 84",
        "48 33 f6 90 48 85 f6 0f 84",
        0,
        bytes.fromhex("48 8b 70 38"),
        bytes.fromhex("48 33 f6 90"),
    )


def patch_native_image_rsi_null_kick(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "Kick Ninja NativeImageType factory fallback rsi -> null",
        "48 8b 44 24 40 48 8b 70 38 48 85 f6 74 0a",
        "48 8b 44 24 40 48 33 f6 90 48 85 f6 74 0a",
        5,
        bytes.fromhex("48 8b 70 38"),
        bytes.fromhex("48 33 f6 90"),
    )


def patch_set_rendering_engine_movsxd(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "HWNDComponentPeer::setCurrentRenderingEngine movsxd edi, edx -> xor edi, edi",
        "83 fa 01 0f 87 ?? ?? ?? ?? 48 63 fa 48 89 ce",
        "83 fa 01 0f 87 ?? ?? ?? ?? 33 ff 90 48 89 ce",
        9,
        bytes.fromhex("48 63 fa"),
        bytes.fromhex("33 ff 90"),
    )


def patch_set_rendering_engine_movsxd_kick(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "Kick Ninja setCurrentRenderingEngine movsxd edi, edx -> xor edi, edi",
        "48 89 5c 24 08 57 48 83 ec 20 48 63 fa 48 8b d9 8b cf ba 02 00 00 00 "
        "e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 48 83 bb 38 02 00 00 00",
        "48 89 5c 24 08 57 48 83 ec 20 33 ff 90 48 8b d9 8b cf ba 02 00 00 00 "
        "e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? ?? ?? 48 83 bb 38 02 00 00 00",
        10,
        bytes.fromhex("48 63 fa"),
        bytes.fromhex("33 ff 90"),
    )


def patch_set_rendering_engine_mov(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "HWNDComponentPeer::setCurrentRenderingEngine mov edi, edx -> xor edi, edi",
        "83 fa 01 0f 87 ?? ?? ?? ?? 89 d7 48 89 ce",
        "83 fa 01 0f 87 ?? ?? ?? ?? 33 ff 48 89 ce",
        9,
        bytes.fromhex("89 d7"),
        bytes.fromhex("33 ff"),
    )


def find_renderer_descriptor(data: bytearray, pe: PEImage) -> tuple[int, int, int] | None:
    sw_strings = find_c_string(data, "Software Renderer")
    d2d_strings = find_c_string(data, "Direct2D")
    candidates: list[tuple[int, int, int]] = []

    for sw_raw in sw_strings:
        sw_va = pe.raw_to_va(sw_raw)
        if sw_va is None:
            continue

        sw_ptr = struct.pack("<Q", sw_va)
        start = 0
        while True:
            table = data.find(sw_ptr, start)
            if table < 0:
                break
            start = table + 1

            if table + 32 > len(data):
                continue

            d2d_name_va = qword(data, table + 16)
            d2d_name_raw = pe.va_to_raw(d2d_name_va)
            if d2d_name_raw not in d2d_strings:
                continue

            gdi_ctor = qword(data, table + 8)
            d2d_ctor = qword(data, table + 24)
            if pe.va_to_raw(gdi_ctor) is None or pe.va_to_raw(d2d_ctor) is None:
                continue

            candidates.append((table, gdi_ctor, d2d_ctor))

    if len(candidates) != 1:
        return None

    return candidates[0]


def patch_renderer_descriptor_to_gdi(data: bytearray, pe: PEImage) -> PatchOutcome:
    found = find_renderer_descriptor(data, pe)
    description = "JUCE renderer descriptor Direct2D constructor -> GDI constructor"

    if found is None:
        return PatchOutcome(description, "missing", "unique descriptor table not found")

    table, gdi_ctor, d2d_ctor = found
    slot = table + 24

    if d2d_ctor == gdi_ctor:
        return PatchOutcome(description, "already", f"raw 0x{slot:x}")

    data[slot : slot + 8] = struct.pack("<Q", gdi_ctor)
    return PatchOutcome(description, "patched", f"raw 0x{slot:x}: 0x{d2d_ctor:x} -> 0x{gdi_ctor:x}")


def patch_inline_d2d_context_to_gdi(data: bytearray, pe: PEImage) -> PatchOutcome:
    description = "inlined D2DRenderContext construction -> GDI factory"
    found = find_renderer_descriptor(data, pe)
    if found is None:
        return PatchOutcome(description, "missing", "unique descriptor table not found")

    _table, gdi_ctor, _d2d_ctor = found

    already = find_pattern(
        data,
        "48 8d 4d 48 48 8b 55 58 e8 ?? ?? ?? ?? 48 8b 55 48 48 8b 75 58 e9",
    )
    old = find_pattern(
        data,
        "b9 30 00 00 00 e8 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? "
        "48 89 08 48 8b 55 58 48 89 50 08 48 89 c1 48 83 c1 10 "
        "48 89 45 48 e8 ?? ?? ?? ?? 48 8b 75 48 48 c7 46 18 00 00 00 00 "
        "48 c7 46 20 00 04 00 00 b9 00 04 00 00",
    )

    if already and not old:
        return PatchOutcome(description, "already", f"{len(already)} already-patched match(es)")

    if len(old) == 0:
        return PatchOutcome(description, "missing", "signature not found")

    if len(old) > 1:
        return PatchOutcome(description, "error", f"ambiguous signature: {len(old)} matches")

    start = old[0]
    common = bytes.fromhex("48 8b 8e 38 02 00 00 48 89 96 38 02 00 00")
    end = data.find(common, start, start + 0x220)
    if end < 0:
        return PatchOutcome(description, "error", "common render-context install block not found")

    start_va = pe.raw_to_va(start)
    end_va = pe.raw_to_va(end)
    if start_va is None or end_va is None:
        return PatchOutcome(description, "error", "could not map raw offsets to VAs")

    code = bytearray()
    code += bytes.fromhex("48 8d 4d 48")  # lea rcx, [rbp+0x48]
    code += bytes.fromhex("48 8b 55 58")  # mov rdx, [rbp+0x58]

    call_site = start_va + len(code)
    code += b"\xe8" + struct.pack("<i", gdi_ctor - (call_site + 5))

    code += bytes.fromhex("48 8b 55 48")  # mov rdx, [rbp+0x48]
    code += bytes.fromhex("48 8b 75 58")  # mov rsi, [rbp+0x58]

    jmp_site = start_va + len(code)
    code += b"\xe9" + struct.pack("<i", end_va - (jmp_site + 5))

    patch_len = end - start
    if len(code) > patch_len:
        return PatchOutcome(description, "error", "replacement longer than original block")

    data[start:end] = bytes(code) + b"\x90" * (patch_len - len(code))
    return PatchOutcome(description, "patched", f"raw 0x{start:x}..0x{end:x}")

def patch_d3d11_create_device_fail(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "D3D11CreateDevice call -> mov eax, E_FAIL",
        "41 b9 20 00 00 00 45 33 c0 33 d2 48 8b 4b 28 e8 ?? ?? ?? ?? 85 c0",
        "41 b9 20 00 00 00 45 33 c0 33 d2 48 8b 4b 28 b8 05 40 00 80 85 c0",
        15,
        bytes.fromhex("e8 0c a4 5c 00"),
        bytes.fromhex("b8 05 40 00 80"),
    )

def patch_dxgi_create_factory_fail(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "CreateDXGIFactory2 call -> mov eax, E_FAIL",
        "4c 8d 44 24 48 48 8d 15 ?? ?? ?? ?? 33 c9 e8 ?? ?? ?? ?? 85 c0",
        "4c 8d 44 24 48 48 8d 15 ?? ?? ?? ?? 33 c9 b8 05 40 00 80 85 c0",
        14,
        bytes.fromhex("e8 52 9b 5c 00"),
        bytes.fromhex("b8 05 40 00 80"),
    )

def patch_dcomp_create_device_fail(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "DCompositionCreateDevice call -> mov eax, E_FAIL",
        "4c 8d 45 e8 48 8d 15 ?? ?? ?? ?? 48 8b c8 e8 ?? ?? ?? ?? 85 c0",
        "4c 8d 45 e8 48 8d 15 ?? ?? ?? ?? 48 8b c8 b8 05 40 00 80 85 c0",
        14,
        bytes.fromhex("e8 a9 fd 3d 00"),
        bytes.fromhex("b8 05 40 00 80"),
    )

def patch_d2d1_create_factory_fail(data: bytearray, pe: PEImage) -> PatchOutcome:
    del pe
    return patch_pattern_bytes(
        data,
        "D2D1CreateFactory call -> mov eax, E_FAIL",
        "4c 8d 44 24 38 48 8d 15 ?? ?? ?? ?? 8d 48 01 e8 ?? ?? ?? ?? 90 48 8b 0b",
        "4c 8d 44 24 38 48 8d 15 ?? ?? ?? ?? 8d 48 01 b8 05 40 00 80 90 48 8b 0b",
        15,
        bytes.fromhex("e8 b8 9a 5c 00"),
        bytes.fromhex("b8 05 40 00 80"),
    )


RECIPES: dict[str, PluginRecipe] = {
    "filterverse": PluginRecipe(
        slug="filterverse",
        display_name="Polyverse Filterverse",
        status="confirmed",
        default_path=HOME
        / ".wine/drive_c/Program Files/Common Files/VST3/Filterverse.vst3/Contents/x86_64-win/Filterverse.vst3",
        patchers=[
            patch_native_image_r14_null,
            patch_set_rendering_engine_mov,
            patch_inline_d2d_context_to_gdi,
        ],
    ),
    "temperance-pro": PluginRecipe(
        slug="temperance-pro",
        display_name="Eventide Temperance Pro",
        status="confirmed",
        default_path=HOME
        / ".wine/drive_c/Program Files/Common Files/VST3/Eventide/Temperance Pro.vst3/Contents/x86_64-win/Temperance Pro.vst3",
        patchers=[patch_create_new_peer_engine_zero_temperance],
    ),
    "temperance-lite": PluginRecipe(
        slug="temperance-lite",
        display_name="Eventide Temperance Lite",
        status="confirmed",
        default_path=HOME
        / ".wine/drive_c/Program Files/Common Files/VST3/Eventide/Temperance Lite.vst3/Contents/x86_64-win/Temperance Lite.vst3",
        patchers=[patch_create_new_peer_engine_zero_temperance],
    ),
    "soothe3": PluginRecipe(
        slug="soothe3",
        display_name="oeksound soothe3",
        status="blocked-protected",
        default_path=HOME
        / ".wine/drive_c/Program Files/Common Files/VST3/soothe3.vst3/Contents/x86_64-win/soothe3.vst3",
        patchers=[],
    ),
    "kick-ninja": PluginRecipe(
        slug="kick-ninja",
        display_name="The Him DSP Kick Ninja",
        status="experimental",
        default_path=HOME
        / ".wine/drive_c/Program Files/Common Files/VST3/The Him DSP/Kick Ninja.vst3/Contents/x86_64-win/Kick Ninja.vst3",
        patchers=[
            patch_create_new_peer_engine_zero_kick,
            patch_native_image_rsi_null_kick,
            patch_set_rendering_engine_movsxd_kick,
            patch_renderer_descriptor_to_gdi,
        ],
    ),
}


PROBE_PATCHERS: list[Callable[[bytearray, PEImage], PatchOutcome]] = [
    patch_create_new_peer_engine_zero,
    patch_create_new_peer_engine_zero_temperance,
    patch_create_new_peer_engine_zero_kick,
    patch_native_image_r14_null,
    patch_native_image_rsi_null,
    patch_native_image_rsi_null_kick,
    patch_set_rendering_engine_movsxd,
    patch_set_rendering_engine_movsxd_kick,
    patch_set_rendering_engine_mov,
    patch_renderer_descriptor_to_gdi,
    patch_inline_d2d_context_to_gdi,
    patch_d3d11_create_device_fail,
    patch_dxgi_create_factory_fail,
    patch_dcomp_create_device_fail,
    patch_d2d1_create_factory_fail,
]


def probe_patchers(
    data: bytes | bytearray,
    pe: PEImage,
    patchers: list[Callable[[bytearray, PEImage], PatchOutcome]],
) -> list[PatchOutcome]:
    return [patcher(bytearray(data), pe) for patcher in patchers]


def juce_version_strings(data: bytes | bytearray) -> list[str]:
    versions: list[str] = []
    for match in re.finditer(rb"JUCE v\d+(?:\.\d+)+", bytes(data)):
        text = match.group(0).decode("ascii")
        if text not in versions:
            versions.append(text)
    return versions


def probe_one(path: Path) -> int:
    print(f"\n== Probe {path} ==")
    if not path.exists():
        print("missing: file does not exist")
        return 1

    data = path.read_bytes()
    try:
        pe = PEImage(data)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1

    print(f"sha256: {hashlib.sha256(data).hexdigest()}")
    versions = juce_version_strings(data)
    if versions:
        print("juce: " + ", ".join(versions))
    else:
        print("juce: no JUCE version string found")

    outcomes = probe_patchers(data, pe, PROBE_PATCHERS)
    hits = [outcome for outcome in outcomes if outcome.status in {"patched", "already"}]
    if not hits:
        print("probe: no known patch signatures matched")
        return 0

    print("probe: matching known patch signatures")
    for outcome in hits:
        suffix = f" - {outcome.detail}" if outcome.detail else ""
        print(f"{outcome.status:8} {outcome.description}{suffix}")
    return 0


def probe_paths(paths: list[Path]) -> int:
    rc = 0
    for path in paths:
        rc |= probe_one(path.expanduser())
    return rc

def parse_selection(raw: str, slugs: list[str]) -> set[str]:
    text = raw.strip().lower()
    if text == "all":
        return set(slugs)
    if text in {"", "none", "q", "quit"}:
        return set()

    selected: set[str] = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        try:
            index = int(part)
        except ValueError as exc:
            raise ValueError(f"invalid selection: {part}") from exc
        if index < 1 or index > len(slugs):
            raise ValueError(f"selection out of range: {index}")
        selected.add(slugs[index - 1])
    return selected


def select_plugins(overrides: dict[str, Path]) -> set[str]:
    slugs = sorted(RECIPES)
    print("Known plugin recipes:")
    for index, slug in enumerate(slugs, start=1):
        recipe = RECIPES[slug]
        path = overrides.get(slug, recipe.default_path)
        marker = "found" if path.exists() else "missing"
        print(f"{index:2d}. {slug:16} {recipe.status:17} {marker:7} {recipe.display_name}")

    while True:
        raw = input("\nSelect plugins to patch (e.g. 1,3 or all; empty to cancel): ")
        try:
            return parse_selection(raw, slugs)
        except ValueError as exc:
            print(f"error: {exc}")




def status_allowed(recipe: PluginRecipe, args: argparse.Namespace, explicit: bool) -> bool:
    if explicit:
        return True
    if args.all_known:
        return True
    if recipe.status == "confirmed":
        return True
    if recipe.status == "testing" and args.include_testing:
        return True
    if recipe.status == "experimental" and args.include_experimental:
        return True
    return False


def make_backup(path: Path, backup_root: Path, slug: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = backup_root / f"juce8-megapatcher-{slug}-{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_path = backup_dir / f"{path.name}.orig"
    shutil.copy2(path, backup_path)
    return backup_path


def parse_path_overrides(values: list[str]) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"--path must look like slug=/path/to/plugin, got: {value}")
        slug, path = value.split("=", 1)
        if slug not in RECIPES:
            raise SystemExit(f"unknown plugin slug in --path: {slug}")
        out[slug] = Path(path).expanduser()
    return out


def patch_one(recipe: PluginRecipe, path: Path, backup_root: Path, dry_run: bool) -> int:
    print(f"\n== {recipe.display_name} ({recipe.slug}, {recipe.status}) ==")
    print(f"path: {path}")

    if not path.exists():
        print("missing: file does not exist")
        return 0

    original_mode = path.stat().st_mode & 0o7777
    original = path.read_bytes()
    data = bytearray(original)

    try:
        pe = PEImage(original)
    except ValueError as exc:
        print(f"error: {exc}")
        return 1

    print(f"sha256: {hashlib.sha256(original).hexdigest()}")

    if not recipe.patchers:
        print("blocked  no static patch recipe is enabled for this plugin")
        print("no write needed")
        return 0

    outcomes = [patcher(data, pe) for patcher in recipe.patchers]
    errors = [o for o in outcomes if o.status == "error"]

    for outcome in outcomes:
        suffix = f" - {outcome.detail}" if outcome.detail else ""
        print(f"{outcome.status:8} {outcome.description}{suffix}")

    if errors:
        print("refusing to write because at least one patch errored")
        return 1

    if data == original:
        print("no write needed")
        return 0

    if dry_run:
        print("dry-run: would write patched binary")
        return 0

    backup = make_backup(path, backup_root, recipe.slug)
    print(f"backup: {backup}")

    os.chmod(path, original_mode | stat.S_IWUSR)
    try:
        path.write_bytes(data)
    finally:
        os.chmod(path, original_mode)

    print(f"new sha256: {hashlib.sha256(path.read_bytes()).hexdigest()}")
    print(f"mode restored: {oct(path.stat().st_mode & 0o7777)}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="show what would be patched without writing")
    parser.add_argument("--list", action="store_true", help="list known plugin slugs")
    parser.add_argument("--all-known", action="store_true", help="include confirmed, testing, and experimental recipes")
    parser.add_argument("--include-testing", action="store_true", help="include recipes marked testing")
    parser.add_argument("--include-experimental", action="store_true", help="include recipes marked experimental")
    parser.add_argument("--plugin", action="append", choices=sorted(RECIPES), help="patch only this plugin slug; can repeat")
    parser.add_argument("--path", action="append", default=[], help="override plugin path: slug=/path/to/binary")
    parser.add_argument("--select", action="store_true", help="show an interactive plugin picker before patching")
    parser.add_argument("--probe", action="append", type=Path, help="scan an arbitrary plugin binary for known signatures without writing")
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT, help="directory for backups")
    args = parser.parse_args(argv)

    if args.list:
        for slug, recipe in RECIPES.items():
            print(f"{slug:14} {recipe.status:12} {recipe.display_name}")
        return 0
    if args.probe:
        return probe_paths(args.probe)

    overrides = parse_path_overrides(args.path)
    explicit = set(args.plugin or [])
    if args.select:
        selected = select_plugins(overrides)
        explicit = set(selected)
    else:
        selected = explicit or set(RECIPES)

    if args.select and not selected:
        print("no plugins selected")
        return 0

    skipped = []
    rc = 0
    for slug in sorted(selected):
        recipe = RECIPES[slug]
        is_explicit = slug in explicit
        if not status_allowed(recipe, args, is_explicit):
            skipped.append(recipe)
            continue

        path = overrides.get(slug, recipe.default_path)
        rc |= patch_one(recipe, path, args.backup_root.expanduser(), args.dry_run)

    if skipped:
        print("\nSkipped non-confirmed recipes:")
        for recipe in skipped:
            print(f"- {recipe.slug}: {recipe.status}")
        print("Use --include-testing, --include-experimental, --all-known, or --plugin SLUG to include them.")

    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
