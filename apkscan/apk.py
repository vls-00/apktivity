"""APK wrapper: manifest model, resources, dex access and signing certificates."""
from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Set

from .arsc import ResourceTable
from .axml import Element, TYPE_REFERENCE, TypedValue, parse_axml
from .dex import DexFile, DexPool

LAUNCH_MODES = {0: "standard", 1: "singleTop", 2: "singleTask", 3: "singleInstance", 4: "singleInstancePerTask"}

API_NAMES = {
    16: "4.1", 17: "4.2", 18: "4.3", 19: "4.4", 20: "4.4W", 21: "5.0", 22: "5.1", 23: "6.0",
    24: "7.0", 25: "7.1", 26: "8.0", 27: "8.1", 28: "9", 29: "10", 30: "11", 31: "12",
    32: "12L", 33: "13", 34: "14", 35: "15", 36: "16",
}


def api_label(level):
    if level is None:
        return "unknown"
    if level in API_NAMES:
        return "API %d (Android %s)" % (level, API_NAMES[level])
    return "API %d" % level


@dataclass
class DataSpec:
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    path_advanced_pattern: Optional[str] = None
    path_suffix: Optional[str] = None
    mime_type: Optional[str] = None
    ssp: Optional[str] = None
    ssp_prefix: Optional[str] = None
    ssp_pattern: Optional[str] = None

    def path_entries(self):
        out = []
        for kind, val in (("path", self.path), ("pathPrefix", self.path_prefix), ("pathPattern", self.path_pattern),
                          ("pathAdvancedPattern", self.path_advanced_pattern), ("pathSuffix", self.path_suffix)):
            if val is not None:
                out.append((kind, val))
        return out


@dataclass
class IntentFilter:
    actions: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    data: List[DataSpec] = field(default_factory=list)
    auto_verify: bool = False
    priority: Optional[int] = None
    line: int = 0

    def schemes(self):
        return _uniq(d.scheme for d in self.data if d.scheme)

    def authorities(self):
        return _uniq((d.host, d.port) for d in self.data if d.host)

    def paths(self):
        return _uniq(p for d in self.data for p in d.path_entries())

    def mime_types(self):
        return _uniq(d.mime_type for d in self.data if d.mime_type)

    def ssps(self):
        """scheme-specific-part matchers (ssp / sspPrefix / sspPattern), e.g. mailto:, tel:, sms:"""
        out = []
        for d in self.data:
            for kind, val in (("ssp", d.ssp), ("sspPrefix", d.ssp_prefix), ("sspPattern", d.ssp_pattern)):
                if val is not None:
                    out.append((kind, val))
        return _uniq(out)

    def has_category(self, short):
        return "android.intent.category." + short in self.categories

    def has_action(self, short):
        return "android.intent.action." + short in self.actions

    def is_launcher(self):
        return self.has_action("MAIN") and (self.has_category("LAUNCHER") or self.has_category("LEANBACK_LAUNCHER"))

    def is_browsable(self):
        return self.has_category("BROWSABLE")


@dataclass
class Component:
    kind: str                     # activity | activity-alias | service | receiver | provider
    name: str
    exported_attr: Optional[bool]
    permission: Optional[str]
    enabled: Optional[bool]
    intent_filters: List[IntentFilter]
    launch_mode: Optional[str] = None
    task_affinity: Optional[str] = None      # None = not set, "" = explicitly empty
    allow_task_reparenting: Optional[bool] = None
    target_activity: Optional[str] = None    # activity-alias only
    element: Optional[Element] = field(default=None, repr=False, compare=False)

    @property
    def short_name(self):
        return self.name.rsplit(".", 1)[-1]

    def is_exported(self, target_sdk=None):
        if self.exported_attr is not None:
            return self.exported_attr
        # no explicit value: exported iff there is an intent filter (target 31+ rejects that at install time anyway)
        return bool(self.intent_filters)

    def exported_reason(self, target_sdk=None):
        if self.exported_attr is True:
            return 'android:exported="true"'
        if self.exported_attr is False:
            return 'android:exported="false"'
        if self.intent_filters:
            return "implicitly exported (has <intent-filter>, no android:exported)"
        return "not exported (no android:exported, no <intent-filter>)"

    def is_launcher(self):
        return any(f.is_launcher() for f in self.intent_filters)

    def is_enabled(self):
        return self.enabled is not False


@dataclass
class Manifest:
    package: str
    version_name: Optional[str]
    version_code: Optional[int]
    min_sdk: Optional[int]
    target_sdk: Optional[int]
    max_sdk: Optional[int]
    uses_permissions: List[str]
    app_task_affinity: Optional[str]
    app_allow_task_reparenting: Optional[bool]
    debuggable: Optional[bool]
    activities: List[Component]          # activities and activity-aliases
    services: List[Component]
    receivers: List[Component]
    providers: List[Component]
    root: Element = field(default=None, repr=False, compare=False)

    def activity(self, name):
        for a in self.activities:
            if a.name == name and a.kind == "activity":
                return a
        return None

    def effective_target(self):
        return self.target_sdk if self.target_sdk is not None else self.min_sdk


def _uniq(items):
    out = []
    for i in items:
        if i not in out:
            out.append(i)
    return out


class APK:
    def __init__(self, path):
        self.path = path
        self.zip = zipfile.ZipFile(path)
        self._names: Set[str] = set(self.zip.namelist())
        self.resources: Optional[ResourceTable] = None
        self.resources_error = None
        self._dex = None

        if "resources.arsc" in self._names:
            try:
                self.resources = ResourceTable(self.zip.read("resources.arsc"))
            except Exception as e:
                self.resources_error = str(e)   # keep going, references just stay unresolved
        if "AndroidManifest.xml" not in self._names:
            raise ValueError("no AndroidManifest.xml in archive")
        self.manifest_root = parse_axml(self.zip.read("AndroidManifest.xml"))
        self.manifest = self._build_manifest(self.manifest_root)

    def has(self, name):
        return name in self._names

    def read(self, name):
        return self.zip.read(name)

    def names(self):
        return self._names

    @property
    def dex(self) -> DexPool:
        if self._dex is None:
            dexes = []
            for n in sorted(self._names, key=_dex_order):
                if re.fullmatch(r"classes\d*\.dex", n):
                    try:
                        dexes.append(DexFile(self.zip.read(n), n))
                    except Exception:
                        pass
            self._dex = DexPool(dexes)
        return self._dex

    # resources / attribute helpers

    def resolve(self, value: Optional[TypedValue]) -> Optional[str]:
        if value is None:
            return None
        if value.data_type == TYPE_REFERENCE:
            if self.resources:
                r = self.resources.resolve_string(value.data)
                if r is not None:
                    return r
            return "@0x%08x" % value.data
        v = value.as_python()
        if v is None:
            return None
        if isinstance(v, bool):
            return "true" if v else "false"
        return str(v)

    def elem_str(self, el, name):
        return self.resolve(el.attr(name))

    def elem_bool(self, el, name):
        tv = el.attr(name)
        if tv is None:
            return None
        if tv.data_type == TYPE_REFERENCE and self.resources:
            return self.resources.resolve_bool(tv.data)
        return el.get_bool(name)

    def elem_int(self, el, name):
        s = self.elem_str(el, name)
        if s is None:
            return None
        try:
            return int(s, 0)
        except ValueError:
            return None

    def layout_files(self):
        return sorted(n for n in self._names if re.match(r"res/layout[^/]*/.*\.xml$", n))

    def parse_xml(self, name):
        if name not in self._names:
            return None
        try:
            return parse_axml(self.zip.read(name))
        except Exception:
            return None

    def layout_path(self, res_id):
        if not self.resources:
            return None
        p = self.resources.resolve_string(res_id)
        return p if p and p in self._names else None

    # manifest

    def _qualify(self, name, package):
        if name is None:
            return None
        if name.startswith("."):
            return package + name
        if "." not in name:
            return package + "." + name
        return name

    def _parse_filter(self, el):
        f = IntentFilter(line=el.line)
        f.auto_verify = bool(self.elem_bool(el, "autoVerify"))
        f.priority = self.elem_int(el, "priority")
        f.actions = [n for n in (self.elem_str(a, "name") for a in el.find_all("action")) if n]
        f.categories = [n for n in (self.elem_str(c, "name") for c in el.find_all("category")) if n]
        for d in el.find_all("data"):
            f.data.append(DataSpec(
                scheme=self.elem_str(d, "scheme"), host=self.elem_str(d, "host"), port=self.elem_str(d, "port"),
                path=self.elem_str(d, "path"), path_prefix=self.elem_str(d, "pathPrefix"),
                path_pattern=self.elem_str(d, "pathPattern"), path_advanced_pattern=self.elem_str(d, "pathAdvancedPattern"),
                path_suffix=self.elem_str(d, "pathSuffix"), mime_type=self.elem_str(d, "mimeType"),
                ssp=self.elem_str(d, "ssp"), ssp_prefix=self.elem_str(d, "sspPrefix"), ssp_pattern=self.elem_str(d, "sspPattern"),
            ))
        return f

    def _parse_component(self, el, package):
        lm = self.elem_str(el, "launchMode")
        if lm is not None and lm.isdigit():
            lm = LAUNCH_MODES.get(int(lm), lm)
        return Component(
            kind=el.name,
            name=self._qualify(self.elem_str(el, "name"), package) or "<unnamed>",
            exported_attr=self.elem_bool(el, "exported"),
            permission=self.elem_str(el, "permission"),
            enabled=self.elem_bool(el, "enabled"),
            intent_filters=[self._parse_filter(f) for f in el.find_all("intent-filter")],
            launch_mode=lm,
            task_affinity=self.elem_str(el, "taskAffinity"),
            allow_task_reparenting=self.elem_bool(el, "allowTaskReparenting"),
            target_activity=self._qualify(self.elem_str(el, "targetActivity"), package),
            element=el,
        )

    def _build_manifest(self, root):
        package = ""
        for a in root.attributes:      # 'package' has no namespace
            if a.name == "package" and a.value.raw_string:
                package = a.value.raw_string

        min_sdk = target_sdk = max_sdk = None
        for us in root.find_all("uses-sdk"):
            min_sdk = self.elem_int(us, "minSdkVersion") or min_sdk
            target_sdk = self.elem_int(us, "targetSdkVersion") or target_sdk
            max_sdk = self.elem_int(us, "maxSdkVersion") or max_sdk

        perms = []
        for p in root.find_all("uses-permission") + root.find_all("uses-permission-sdk-23"):
            n = self.elem_str(p, "name")
            if n:
                perms.append(n)

        buckets = {"activity": [], "activity-alias": [], "service": [], "receiver": [], "provider": []}
        app = root.find("application")
        app_affinity = app_reparent = debuggable = None
        if app is not None:
            app_affinity = self.elem_str(app, "taskAffinity")
            app_reparent = self.elem_bool(app, "allowTaskReparenting")
            debuggable = self.elem_bool(app, "debuggable")
            for child in app.children:
                if child.name in buckets:
                    buckets[child.name].append(self._parse_component(child, package))

        return Manifest(
            package=package,
            version_name=self.elem_str(root, "versionName"),
            version_code=self.elem_int(root, "versionCode"),
            min_sdk=min_sdk, target_sdk=target_sdk, max_sdk=max_sdk,
            uses_permissions=perms,
            app_task_affinity=app_affinity, app_allow_task_reparenting=app_reparent, debuggable=debuggable,
            activities=buckets["activity"] + buckets["activity-alias"],
            services=buckets["service"], receivers=buckets["receiver"], providers=buckets["provider"],
            root=root,
        )

    # signing

    def signing_cert_sha256(self) -> List[str]:
        """Colon separated SHA-256 fingerprints of the signing certs (v2/v3 block, else v1 META-INF)."""
        try:
            certs = self._v2v3_certs()
        except Exception:
            certs = []
        if not certs:
            for n in self._names:
                if n.startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC")):
                    try:
                        certs.extend(_pkcs7_certs(self.zip.read(n)))
                    except Exception:
                        pass
        out = []
        for c in certs:
            h = hashlib.sha256(c).hexdigest().upper()
            fp = ":".join(h[i:i + 2] for i in range(0, len(h), 2))
            if fp not in out:
                out.append(fp)
        return out

    def _v2v3_certs(self):
        with open(self.path, "rb") as fh:
            data = fh.read()
        eocd = data.rfind(b"PK\x05\x06")
        if eocd < 0:
            return []
        cd_off = struct.unpack_from("<I", data, eocd + 16)[0]
        if cd_off < 24 or data[cd_off - 16:cd_off] != b"APK Sig Block 42":
            return []
        block_size = struct.unpack_from("<Q", data, cd_off - 24)[0]
        off = cd_off - block_size - 8 + 8
        end = cd_off - 24
        certs = []
        while off + 12 <= end:
            length = struct.unpack_from("<Q", data, off)[0]
            pair_id = struct.unpack_from("<I", data, off + 8)[0]
            if pair_id in (0x7109871A, 0xF05368C0):   # v2, v3
                certs.extend(_scheme_block_certs(data[off + 12:off + 8 + length]))
            off += 8 + length
        return certs


def _dex_order(name):
    m = re.fullmatch(r"classes(\d*)\.dex", name)
    return (0, int(m.group(1) or 1)) if m else (1, name)


def _lp(data, off):
    """uint32 length-prefixed slice"""
    n = struct.unpack_from("<I", data, off)[0]
    return data[off + 4:off + 4 + n], off + 4 + n


def _scheme_block_certs(value):
    certs = []
    signers, _ = _lp(value, 0)
    off = 0
    while off + 4 <= len(signers):
        signer, off = _lp(signers, off)
        signed_data, _ = _lp(signer, 0)
        _digests, p = _lp(signed_data, 0)
        cert_seq, _ = _lp(signed_data, p)
        q = 0
        while q + 4 <= len(cert_seq):
            cert, q = _lp(cert_seq, q)
            certs.append(cert)
    return certs


def _der_tlv(data, off):
    tag = data[off]
    length = data[off + 1]
    off += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, off, length


def _der_children(data, start, end):
    off = start
    while off < end:
        tag, voff, length = _der_tlv(data, off)
        yield tag, off, voff, voff + length
        off = voff + length


def _pkcs7_certs(data):
    """Certificates out of a JAR signature block (PKCS#7 SignedData)."""
    _, voff, length = _der_tlv(data, 0)
    for tag, _s, v, _e in _der_children(data, voff, voff + length):
        if tag != 0xA0:
            continue
        _, sd_v, sd_len = _der_tlv(data, v)
        for t2, _s2, v2, e2 in _der_children(data, sd_v, sd_v + sd_len):
            if t2 == 0xA0:
                return [data[s3:e3] for t3, s3, _v3, e3 in _der_children(data, v2, e2) if t3 == 0x30]
    return []
