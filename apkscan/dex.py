"""
Lazy DEX reader.

Covers what the scanners ask: class hierarchy, methods a class invokes, integer and
string constants in its code, and method names it defines. Classes are parsed on
demand so poking at a few activities in a big multidex app is cheap.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

NO_INDEX = 0xFFFFFFFF

# instruction length in 16-bit units, per opcode
_INSN_SIZE = [1] * 256
for _ops, _n in (
    ((0x02, 0x05, 0x08), 2),
    ((0x03, 0x06, 0x09), 3),
    ((0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29), 2),
    ((0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c), 3),
    ((0x18,), 5),
    (range(0x2d, 0x3e), 2),      # cmp / if
    (range(0x44, 0x6e), 2),      # array, iget/iput, sget/sput
    (range(0x6e, 0x73), 3),      # invoke
    (range(0x74, 0x79), 3),      # invoke/range
    (range(0x90, 0xb0), 2),      # binop
    (range(0xd0, 0xe3), 2),      # binop/lit16, lit8
    ((0xfa, 0xfb), 4),           # invoke-polymorphic
    ((0xfc, 0xfd), 3),           # invoke-custom
    ((0xfe, 0xff), 2),
):
    for _o in _ops:
        _INSN_SIZE[_o] = _n

INVOKE_OPS = set(range(0x6e, 0x73)) | set(range(0x74, 0x79))
OP_CONST_16, OP_CONST, OP_CONST_HIGH16 = 0x13, 0x14, 0x15
OP_CONST_STRING, OP_CONST_STRING_JUMBO = 0x1a, 0x1b


def uleb128(data, off):
    result = shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


@dataclass
class MethodDef:
    method_idx: int
    access_flags: int
    code_off: int


@dataclass
class ClassDef:
    name: str
    superclass: Optional[str]
    interfaces: List[str]
    access_flags: int
    class_data_off: int
    dex: "DexFile"
    _methods: Optional[List[MethodDef]] = field(default=None, repr=False)

    def methods(self):
        if self._methods is None:
            self._methods = self.dex._class_data(self.class_data_off)
        return self._methods

    def method_names(self) -> Set[str]:
        return {self.dex.method_name(m.method_idx) for m in self.methods()}

    def instructions(self) -> Iterator[Tuple[int, int, int]]:
        """(opcode, offset, end_of_code) for every instruction in every method."""
        d = self.dex.data
        for m in self.methods():
            if not m.code_off:
                continue
            try:
                insns = struct.unpack_from("<I", d, m.code_off + 12)[0]
            except struct.error:
                continue
            off = m.code_off + 16
            end = off + insns * 2
            while off + 2 <= end:
                op = d[off]
                if op == 0 and d[off + 1] in (1, 2, 3):
                    # switch / fill-array payload sitting inline after the code
                    kind = d[off + 1]
                    if kind == 1:
                        units = struct.unpack_from("<H", d, off + 2)[0] * 2 + 4
                    elif kind == 2:
                        units = struct.unpack_from("<H", d, off + 2)[0] * 4 + 2
                    else:
                        width = struct.unpack_from("<H", d, off + 2)[0]
                        count = struct.unpack_from("<I", d, off + 4)[0]
                        units = (count * width + 1) // 2 + 4
                    off += max(units, 1) * 2
                    continue
                yield op, off, end
                off += _INSN_SIZE[op] * 2

    def invoked_methods(self) -> Set[str]:
        d = self.dex.data
        out = set()
        for op, off, end in self.instructions():
            if op in INVOKE_OPS and off + 4 <= end:
                ref = self.dex.method_ref(struct.unpack_from("<H", d, off + 2)[0])
                if ref:
                    out.add(ref)
        return out

    def int_constants(self) -> Set[int]:
        d = self.dex.data
        out = set()
        for op, off, end in self.instructions():
            if op == OP_CONST and off + 6 <= end:
                out.add(struct.unpack_from("<I", d, off + 2)[0])
            elif op == OP_CONST_HIGH16 and off + 4 <= end:
                out.add(struct.unpack_from("<H", d, off + 2)[0] << 16)
            elif op == OP_CONST_16 and off + 4 <= end:
                out.add(struct.unpack_from("<H", d, off + 2)[0])
        return out

    def string_constants(self) -> Set[str]:
        d = self.dex.data
        out = set()
        for op, off, end in self.instructions():
            if op == OP_CONST_STRING and off + 4 <= end:
                s = self.dex.string(struct.unpack_from("<H", d, off + 2)[0])
            elif op == OP_CONST_STRING_JUMBO and off + 6 <= end:
                s = self.dex.string(struct.unpack_from("<I", d, off + 2)[0])
            else:
                continue
            if s is not None:
                out.add(s)
        return out


class DexFile:
    def __init__(self, data: bytes, name="classes.dex"):
        if data[:4] != b"dex\n":
            raise ValueError("%s: not a dex file" % name)
        self.data = data
        self.name = name
        (self.string_ids_size, self.string_ids_off, self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off, self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off, self.class_defs_size, self.class_defs_off,
         ) = struct.unpack_from("<12I", data, 0x38)
        self._strings: Dict[int, str] = {}
        self._classes: Optional[Dict[str, int]] = None

    def string(self, idx) -> Optional[str]:
        if idx >= self.string_ids_size:
            return None
        s = self._strings.get(idx)
        if s is None:
            off = struct.unpack_from("<I", self.data, self.string_ids_off + idx * 4)[0]
            _, off = uleb128(self.data, off)
            s = self.data[off:self.data.index(b"\x00", off)].decode("utf-8", "replace")
            self._strings[idx] = s
        return s

    def type_name(self, idx) -> Optional[str]:
        if idx >= self.type_ids_size:
            return None
        return self.string(struct.unpack_from("<I", self.data, self.type_ids_off + idx * 4)[0])

    def method_ref(self, idx) -> Optional[str]:
        if idx >= self.method_ids_size:
            return None
        cls, _proto, name = struct.unpack_from("<HHI", self.data, self.method_ids_off + idx * 8)
        return "%s->%s" % (self.type_name(cls), self.string(name))

    def method_name(self, idx) -> str:
        _cls, _proto, name = struct.unpack_from("<HHI", self.data, self.method_ids_off + idx * 8)
        return self.string(name) or ""

    def all_strings(self):
        for i in range(self.string_ids_size):
            s = self.string(i)
            if s is not None:
                yield s

    def class_index(self) -> Dict[str, int]:
        if self._classes is None:
            self._classes = {}
            for i in range(self.class_defs_size):
                off = self.class_defs_off + i * 32
                name = self.type_name(struct.unpack_from("<I", self.data, off)[0])
                if name:
                    self._classes[name] = off
        return self._classes

    def class_def(self, name) -> Optional[ClassDef]:
        off = self.class_index().get(name)
        if off is None:
            return None
        _cls, access, super_idx, ifaces_off, _src, _anno, class_data_off, _static = struct.unpack_from("<8I", self.data, off)
        interfaces = []
        if ifaces_off:
            n = struct.unpack_from("<I", self.data, ifaces_off)[0]
            for i in range(n):
                t = self.type_name(struct.unpack_from("<H", self.data, ifaces_off + 4 + i * 2)[0])
                if t:
                    interfaces.append(t)
        superclass = self.type_name(super_idx) if super_idx != NO_INDEX else None
        return ClassDef(name, superclass, interfaces, access, class_data_off, self)

    def _class_data(self, off) -> List[MethodDef]:
        if not off:
            return []
        d = self.data
        static_fields, off = uleb128(d, off)
        instance_fields, off = uleb128(d, off)
        direct, off = uleb128(d, off)
        virtual, off = uleb128(d, off)
        for _ in range(static_fields + instance_fields):
            _, off = uleb128(d, off)
            _, off = uleb128(d, off)
        methods = []
        for count in (direct, virtual):
            idx = 0
            for _ in range(count):
                diff, off = uleb128(d, off)
                access, off = uleb128(d, off)
                code_off, off = uleb128(d, off)
                idx += diff
                methods.append(MethodDef(idx, access, code_off))
        return methods


def to_descriptor(name: str) -> str:
    if name.startswith("L") and name.endswith(";"):
        return name
    return "L" + name.replace(".", "/") + ";"


def to_java(desc: str) -> str:
    if desc.startswith("L") and desc.endswith(";"):
        desc = desc[1:-1]
    return desc.replace("/", ".")


class DexPool:
    """All classes*.dex of an APK behind one lookup."""

    def __init__(self, dexes: List[DexFile]):
        self.dexes = dexes

    def class_def(self, name) -> Optional[ClassDef]:
        desc = to_descriptor(name)
        for dx in self.dexes:
            c = dx.class_def(desc)
            if c is not None:
                return c
        return None

    def superclass_chain(self, name, max_depth=25) -> List[ClassDef]:
        """The class plus every superclass that is shipped inside the APK."""
        chain = []
        seen = set()
        cur = self.class_def(name)
        while cur is not None and cur.name not in seen and len(chain) < max_depth:
            chain.append(cur)
            seen.add(cur.name)
            cur = self.class_def(cur.superclass) if cur.superclass else None
        return chain

    def inner_classes(self, name) -> List[ClassDef]:
        prefix = to_descriptor(name)[:-1] + "$"
        out = []
        for dx in self.dexes:
            for cname in dx.class_index():
                if cname.startswith(prefix):
                    c = dx.class_def(cname)
                    if c:
                        out.append(c)
        return out

    def any_string_contains(self, needle) -> bool:
        return any(needle in s for dx in self.dexes for s in dx.all_strings())

    def classes_invoking(self, method_suffix) -> List[str]:
        """Every class whose code calls a method ref ending in method_suffix. Walks all classes, slow."""
        out = []
        for dx in self.dexes:
            for cname in dx.class_index():
                c = dx.class_def(cname)
                if c and any(r.endswith(method_suffix) for r in c.invoked_methods()):
                    out.append(cname)
        return out
