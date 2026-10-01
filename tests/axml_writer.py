"""
Minimal binary XML writer, only used to build test fixtures.

Elements are (tag, {attr: value}, [children]). Attribute names starting with
"android:" go into the android namespace. Values can be str, bool or int.
"""
from __future__ import annotations

import io
import struct
import zipfile
from typing import Dict, List, Tuple

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ATTR_IDS = {  # android.R.attr ids for the attributes the fixtures use
    "theme": 0x01010000, "label": 0x01010001, "icon": 0x01010002, "name": 0x01010003,
    "permission": 0x01010006, "enabled": 0x0101000e, "exported": 0x01010010,
    "taskAffinity": 0x01010012, "launchMode": 0x0101001d, "scheme": 0x01010027, "host": 0x01010028,
    "port": 0x01010029, "path": 0x0101002a, "pathPrefix": 0x0101002b, "pathPattern": 0x0101002c,
    "mimeType": 0x01010026, "minSdkVersion": 0x0101020c, "versionCode": 0x0101021b,
    "versionName": 0x0101021c, "allowTaskReparenting": 0x0101021d, "targetSdkVersion": 0x01010270,
    "targetActivity": 0x01010202, "filterTouchesWhenObscured": 0x010102c4, "autoVerify": 0x010104ee,
    "pathSuffix": 0x010106cd, "pathAdvancedPattern": 0x010106ce, "ssp": 0x010106c4,
    "sspPrefix": 0x010106c6, "sspPattern": 0x010106c5, "priority": 0x0101001c,
}
_LAUNCH_MODES = {"standard": 0, "singleTop": 1, "singleTask": 2, "singleInstance": 3, "singleInstancePerTask": 4}

Elem = Tuple[str, Dict[str, object], List["Elem"]]


def _walk(el: Elem):
    yield el
    for c in el[2]:
        yield from _walk(c)


def build_axml(root: Elem) -> bytes:
    # android attribute names go first so their indexes line up with the resource map
    attr_names: List[str] = []
    other: List[str] = []

    def add(s: str, is_attr: bool):
        target = attr_names if is_attr else other
        if s not in attr_names and s not in other:
            target.append(s)

    for tag, attrs, _ in _walk(root):
        for k, v in attrs.items():
            if k.startswith("android:"):
                add(k[8:], True)
    for tag, attrs, _ in _walk(root):
        add(tag, False)
        for k, v in attrs.items():
            if not k.startswith("android:"):
                add(k, False)
            if isinstance(v, str):
                add(v, False)
    add("android", False)
    add(ANDROID_NS, False)
    strings = attr_names + other
    idx = {s: i for i, s in enumerate(strings)}

    # string pool chunk (UTF-8)
    encoded = []
    for s in strings:
        b = s.encode("utf-8")
        assert len(b) < 128 and len(s) < 128
        encoded.append(bytes([len(s), len(b)]) + b + b"\x00")
    offsets = []
    pos = 0
    for e in encoded:
        offsets.append(pos)
        pos += len(e)
    body = b"".join(encoded)
    if len(body) % 4:
        body += b"\x00" * (4 - len(body) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    pool = struct.pack("<HHIIIIII", 0x0001, header_size, strings_start + len(body), len(strings), 0, 1 << 8, strings_start, 0)
    pool += struct.pack(f"<{len(strings)}I", *offsets) + body

    # resource map
    res_map = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(attr_names)) + struct.pack(f"<{len(attr_names)}I", *[_ATTR_IDS[n] for n in attr_names])

    out = io.BytesIO()
    out.write(pool)
    out.write(res_map)
    out.write(struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, idx["android"], idx[ANDROID_NS]))

    line = [2]

    def emit(el: Elem):
        tag, attrs, children = el
        line[0] += 1
        attr_bytes = b""
        for k, v in attrs.items():
            if k.startswith("android:"):
                ns, name = idx[ANDROID_NS], idx[k[8:]]
            else:
                ns, name = 0xFFFFFFFF, idx[k]
            if k == "android:launchMode" and isinstance(v, str):
                v = _LAUNCH_MODES[v]
            if isinstance(v, bool):
                raw, dtype, data = 0xFFFFFFFF, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, int):
                raw, dtype, data = 0xFFFFFFFF, 0x10, v & 0xFFFFFFFF
            else:
                raw, dtype, data = idx[v], 0x03, idx[v]
            attr_bytes += struct.pack("<IIIHBBI", ns, name, raw, 8, 0, dtype, data)
        chunk = struct.pack("<IIHHHHHH", 0xFFFFFFFF, idx[tag], 20, 20, len(attrs), 0, 0, 0) + attr_bytes
        out.write(struct.pack("<HHIII", 0x0102, 16, 16 + len(chunk), line[0], 0xFFFFFFFF) + chunk)
        for c in children:
            emit(c)
        out.write(struct.pack("<HHIIIII", 0x0103, 16, 24, line[0], 0xFFFFFFFF, 0xFFFFFFFF, idx[tag]))

    emit(root)
    out.write(struct.pack("<HHIIIII", 0x0101, 16, 24, line[0], 0xFFFFFFFF, idx["android"], idx[ANDROID_NS]))
    content = out.getvalue()
    return struct.pack("<HHI", 0x0003, 8, 8 + len(content)) + content


def build_apk(path: str, manifest: Elem, extra_files: Dict[str, bytes] = None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", build_axml(manifest))
        for name, data in (extra_files or {}).items():
            z.writestr(name, data)


def manifest(package: str, min_sdk: int, target_sdk: int, activities: List[Elem], app_attrs: Dict[str, object] = None,
             permissions: List[str] = None) -> Elem:
    perms = [("uses-permission", {"android:name": p}, []) for p in (permissions or [])]
    return ("manifest", {"package": package, "android:versionCode": 1, "android:versionName": "1.0"},
            perms + [("uses-sdk", {"android:minSdkVersion": min_sdk, "android:targetSdkVersion": target_sdk}, []),
                     ("application", dict(app_attrs or {}), activities)])


def activity(name: str, attrs: Dict[str, object] = None, filters: List[Elem] = None, tag: str = "activity") -> Elem:
    a = {"android:name": name}
    a.update(attrs or {})
    return (tag, a, filters or [])


def intent_filter(actions: List[str], categories: List[str], data: List[Dict[str, object]] = None, auto_verify: bool = None) -> Elem:
    attrs = {}
    if auto_verify is not None:
        attrs["android:autoVerify"] = auto_verify
    children: List[Elem] = [("action", {"android:name": a}, []) for a in actions]
    children += [("category", {"android:name": c}, []) for c in categories]
    children += [("data", {f"android:{k}": v for k, v in d.items()}, []) for d in (data or [])]
    return ("intent-filter", attrs, children)


LAUNCHER = intent_filter(["android.intent.action.MAIN"], ["android.intent.category.LAUNCHER"])
