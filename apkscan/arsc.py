"""resources.arsc reader. Just enough to resolve @references to strings and map layout ids to files."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .axml import StringPool, TYPE_REFERENCE, TYPE_STRING, TYPE_INT_BOOLEAN, TYPE_INT_DEC, TYPE_INT_HEX

RES_TABLE_TYPE = 0x0002
RES_TABLE_PACKAGE_TYPE = 0x0200
RES_TABLE_TYPE_TYPE = 0x0201

ENTRY_FLAG_COMPLEX = 0x0001
ENTRY_FLAG_COMPACT = 0x0008
TYPE_FLAG_SPARSE = 0x01
TYPE_FLAG_OFFSET16 = 0x02


@dataclass
class ResEntry:
    type_name: str
    key: str
    values: List[Tuple[int, int]] = field(default_factory=list)  # (data_type, data), one per config


class ResourceTable:
    def __init__(self, data: bytes):
        self._data = data
        self.global_pool: Optional[StringPool] = None
        self.entries: Dict[int, ResEntry] = {}
        self.packages: Dict[int, str] = {}

        ctype, hsize, size, _count = struct.unpack_from("<HHII", data, 0)
        if ctype != RES_TABLE_TYPE:
            raise ValueError("not a resources.arsc file")
        off = hsize
        end = min(size, len(data))
        while off + 8 <= end:
            ctype, chsize, csize = struct.unpack_from("<HHI", data, off)
            if csize < 8:
                break
            if ctype == 0x0001 and self.global_pool is None:
                self.global_pool = StringPool(data, off)
            elif ctype == RES_TABLE_PACKAGE_TYPE:
                self._parse_package(off, chsize, csize)
            off += csize

    def _parse_package(self, off, hsize, size):
        d = self._data
        pkg_id = struct.unpack_from("<I", d, off + 8)[0]
        name = d[off + 12:off + 268].decode("utf-16-le", "ignore").split("\x00")[0]
        type_strings, _, key_strings, _ = struct.unpack_from("<IIII", d, off + 268)
        self.packages[pkg_id] = name
        type_pool = StringPool(d, off + type_strings) if type_strings else None
        key_pool = StringPool(d, off + key_strings) if key_strings else None

        coff = off + hsize
        while coff + 8 <= off + size:
            ctype, chsize, csize = struct.unpack_from("<HHI", d, coff)
            if csize < 8:
                break
            if ctype == RES_TABLE_TYPE_TYPE:
                try:
                    self._parse_type(coff, chsize, pkg_id, type_pool, key_pool)
                except (struct.error, IndexError):
                    pass  # damaged chunk, skip it
            coff += csize

    def _parse_type(self, off, hsize, pkg_id, type_pool, key_pool):
        d = self._data
        type_id, flags, _res, entry_count, entries_start = struct.unpack_from("<BBHII", d, off + 8)
        type_name = type_pool.get(type_id - 1) if type_pool else "type%d" % type_id
        offsets_off = off + hsize
        base = off + entries_start

        pairs = []
        if flags & TYPE_FLAG_SPARSE:
            for i in range(entry_count):
                idx, eoff = struct.unpack_from("<HH", d, offsets_off + i * 4)
                pairs.append((idx, eoff * 4))
        elif flags & TYPE_FLAG_OFFSET16:
            for i in range(entry_count):
                eoff = struct.unpack_from("<H", d, offsets_off + i * 2)[0]
                if eoff != 0xFFFF:
                    pairs.append((i, eoff * 4))
        else:
            for i in range(entry_count):
                eoff = struct.unpack_from("<I", d, offsets_off + i * 4)[0]
                if eoff != 0xFFFFFFFF:
                    pairs.append((i, eoff))

        for idx, eoff in pairs:
            eaddr = base + eoff
            if eaddr + 8 > len(d):
                continue
            esize, eflags = struct.unpack_from("<HH", d, eaddr)
            res_id = (pkg_id << 24) | (type_id << 16) | idx
            is_bag = False
            if eflags & ENTRY_FLAG_COMPACT:
                # compact entry (Android 14+): key in the size slot, type in the high flag byte
                key_idx = esize
                data_type = eflags >> 8
                data = struct.unpack_from("<I", d, eaddr + 4)[0]
            else:
                key_idx = struct.unpack_from("<I", d, eaddr + 4)[0]
                is_bag = bool(eflags & ENTRY_FLAG_COMPLEX)
                if not is_bag:
                    _, _, data_type, data = struct.unpack_from("<HBBI", d, eaddr + esize)
            key = key_pool.get(key_idx) if key_pool else str(key_idx)
            entry = self.entries.get(res_id)
            if entry is None:
                entry = self.entries[res_id] = ResEntry(type_name or "", key or "")
            if not is_bag:
                entry.values.append((data_type, data))

    def entry(self, res_id):
        return self.entries.get(res_id)

    def name(self, res_id) -> Optional[str]:
        e = self.entries.get(res_id)
        if not e:
            return None
        pkg = self.packages.get(res_id >> 24, "")
        return "@%s%s/%s" % (pkg + ":" if pkg else "", e.type_name, e.key)

    def resolve_string(self, res_id, _depth=0) -> Optional[str]:
        e = self.entries.get(res_id)
        if not e or _depth > 8:
            return None
        for data_type, data in e.values:
            if data_type == TYPE_STRING and self.global_pool:
                return self.global_pool.get(data)
            if data_type == TYPE_REFERENCE and data and data != res_id:
                r = self.resolve_string(data, _depth + 1)
                if r is not None:
                    return r
            if data_type == TYPE_INT_BOOLEAN:
                return "true" if data else "false"
            if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
                return str(data)
        return None

    def resolve_bool(self, res_id) -> Optional[bool]:
        s = self.resolve_string(res_id)
        if s is None:
            return None
        return s.strip().lower() in ("true", "1")

    def layout_ids(self) -> Dict[int, str]:
        return {rid: e.key for rid, e in self.entries.items() if e.type_name == "layout"}

    def find(self, type_name, key) -> Optional[int]:
        for rid, e in self.entries.items():
            if e.type_name == type_name and e.key == key:
                return rid
        return None
