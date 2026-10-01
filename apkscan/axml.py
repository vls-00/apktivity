"""Android binary XML (AXML) parser for AndroidManifest.xml and compiled layouts."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, List, Optional

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android.R.attr ids we care about. Some obfuscators strip attribute names from the
# string pool, in which case the resource map is the only way to know what an attribute is.
ANDROID_ATTR_IDS = {
    0x01010000: "theme", 0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
    0x01010006: "permission", 0x01010007: "readPermission", 0x01010008: "writePermission",
    0x0101000e: "enabled", 0x0101000f: "debuggable", 0x01010010: "exported",
    0x01010011: "process", 0x01010012: "taskAffinity", 0x01010013: "multiprocess",
    0x01010014: "finishOnTaskLaunch", 0x01010015: "clearTaskOnLaunch",
    0x01010016: "stateNotNeeded", 0x01010017: "excludeFromRecents",
    0x01010018: "authorities", 0x0101001b: "grantUriPermissions", 0x0101001c: "priority",
    0x0101001d: "launchMode", 0x0101001e: "screenOrientation", 0x0101001f: "configChanges",
    0x01010020: "description", 0x01010021: "targetPackage", 0x01010024: "value",
    0x01010025: "resource", 0x01010026: "mimeType", 0x01010027: "scheme", 0x01010028: "host",
    0x01010029: "port", 0x0101002a: "path", 0x0101002b: "pathPrefix", 0x0101002c: "pathPattern",
    0x0101002d: "action", 0x0101002e: "data", 0x0101002f: "targetClass",
    0x0101020c: "minSdkVersion", 0x0101021b: "versionCode", 0x0101021c: "versionName",
    0x0101021d: "allowTaskReparenting", 0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion",
    0x01010202: "targetActivity", 0x010102c4: "filterTouchesWhenObscured",
    0x010104ee: "autoVerify",
}


class AXMLError(Exception):
    pass


@dataclass
class TypedValue:
    data_type: int
    data: int
    raw_string: Optional[str] = None

    def is_reference(self):
        return self.data_type == TYPE_REFERENCE

    def as_python(self) -> Any:
        if self.raw_string is not None and self.data_type == TYPE_STRING:
            return self.raw_string
        if self.data_type == TYPE_INT_BOOLEAN:
            return self.data != 0
        if self.data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            return self.data - (1 << 32) if self.data & 0x80000000 else self.data
        if self.data_type == TYPE_REFERENCE:
            return "@0x%08x" % self.data
        if self.data_type == TYPE_ATTRIBUTE:
            return "?0x%08x" % self.data
        if self.data_type == TYPE_FLOAT:
            return struct.unpack("<f", struct.pack("<I", self.data))[0]
        if self.data_type == TYPE_NULL:
            return None
        if self.raw_string is not None:
            return self.raw_string
        return self.data


@dataclass
class Attribute:
    namespace: Optional[str]
    name: str
    value: TypedValue
    resource_id: Optional[int] = None


@dataclass
class Element:
    name: str
    namespace: Optional[str] = None
    attributes: List[Attribute] = field(default_factory=list)
    children: List["Element"] = field(default_factory=list)
    parent: Optional["Element"] = field(default=None, repr=False, compare=False)
    line: int = 0

    def attr(self, name, namespace=ANDROID_NS) -> Optional[TypedValue]:
        fallback = None
        for a in self.attributes:
            if a.name != name:
                continue
            if namespace is None or a.namespace == namespace:
                return a.value
            if a.namespace is None and fallback is None:
                fallback = a.value  # manifests with a broken/missing namespace
        return fallback

    def get(self, name, default=None, namespace=ANDROID_NS):
        v = self.attr(name, namespace)
        return default if v is None else v.as_python()

    def get_str(self, name, default=None):
        v = self.get(name)
        return default if v is None else str(v)

    def get_bool(self, name) -> Optional[bool]:
        v = self.attr(name)
        if v is None:
            return None
        if v.data_type == TYPE_INT_BOOLEAN:
            return v.data != 0
        if v.data_type == TYPE_STRING and v.raw_string is not None:
            s = v.raw_string.strip().lower()
            if s in ("true", "1"):
                return True
            if s in ("false", "0"):
                return False
        if v.data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
            return v.data != 0
        return None

    def find_all(self, name):
        return [c for c in self.children if c.name == name]

    def find(self, name):
        for c in self.children:
            if c.name == name:
                return c
        return None

    def iter(self):
        yield self
        for c in self.children:
            yield from c.iter()


class StringPool:
    def __init__(self, data: bytes, offset: int):
        (chunk_type, header_size, chunk_size, count, _styles, flags,
         strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, offset)
        if chunk_type != RES_STRING_POOL_TYPE:
            raise AXMLError("expected string pool at 0x%x, got 0x%04x" % (offset, chunk_type))
        self.size = chunk_size
        self.utf8 = bool(flags & (1 << 8))
        self._cache: List[Optional[str]] = [None] * count
        self._data = data
        self._base = offset + strings_start
        self._offsets = struct.unpack_from("<%dI" % count, data, offset + header_size)

    def __len__(self):
        return len(self._cache)

    def get(self, idx: int) -> Optional[str]:
        if idx < 0 or idx >= len(self._cache):
            return None
        s = self._cache[idx]
        if s is None:
            s = self._decode(self._base + self._offsets[idx])
            self._cache[idx] = s
        return s

    def _decode(self, off):
        d = self._data
        try:
            if self.utf8:
                # utf-16 length, then utf-8 byte length, both 1 or 2 bytes
                off += 2 if d[off] & 0x80 else 1
                n = d[off]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | d[off + 1]
                    off += 2
                else:
                    off += 1
                return d[off:off + n].decode("utf-8", "replace")
            n = struct.unpack_from("<H", d, off)[0]
            off += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, off)[0]
                off += 2
            return d[off:off + n * 2].decode("utf-16-le", "replace")
        except (IndexError, struct.error):
            return ""


def parse_axml(data: bytes) -> Element:
    if len(data) < 8:
        raise AXMLError("file too small")
    chunk_type, header_size, file_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != RES_XML_TYPE:
        raise AXMLError("not a binary XML file (type 0x%04x)" % chunk_type)

    off = header_size
    pool = None
    resource_map: List[int] = []
    root = None
    current = None
    end = min(file_size, len(data))

    while off + 8 <= end:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8:
            raise AXMLError("bad chunk size at 0x%x" % off)

        if ctype == RES_STRING_POOL_TYPE:
            pool = StringPool(data, off)
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            n = (csize - chsize) // 4
            resource_map = list(struct.unpack_from("<%dI" % n, data, off + chsize))
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            if pool is None:
                raise AXMLError("element before string pool")
            line = struct.unpack_from("<I", data, off + 8)[0]
            ns_idx, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", data, off + chsize)
            elem = Element(pool.get(name_idx) or "", pool.get(ns_idx) if ns_idx != 0xFFFFFFFF else None,
                           parent=current, line=line)
            aoff = off + chsize + attr_start
            for _ in range(attr_count):
                a_ns, a_name, a_raw, _sz, _r0, a_type, a_data = struct.unpack_from("<IIIHBBI", data, aoff)
                name = pool.get(a_name) or ""
                res_id = None
                if a_name < len(resource_map):
                    res_id = resource_map[a_name]
                    if not name:
                        name = ANDROID_ATTR_IDS.get(res_id, "")
                raw = pool.get(a_raw) if a_raw != 0xFFFFFFFF else None
                if a_type == TYPE_STRING and raw is None:
                    raw = pool.get(a_data)
                ns = pool.get(a_ns) if a_ns != 0xFFFFFFFF else None
                elem.attributes.append(Attribute(ns, name, TypedValue(a_type, a_data, raw), res_id))
                aoff += attr_size
            if current is not None:
                current.children.append(elem)
            elif root is None:
                root = elem
            current = elem
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if current is not None:
                current = current.parent
        # namespace and cdata chunks carry nothing we need
        off += csize

    if root is None:
        raise AXMLError("no root element")
    return root
