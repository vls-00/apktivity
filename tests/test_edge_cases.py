"""
Edge-case and robustness tests, focused on false negatives: cases where a real
issue exists but the scanner could miss it, plus parser hardening so a malformed
APK never silently yields an empty (clean-looking) report.
"""
import os
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from axml_writer import LAUNCHER, activity, build_apk, build_axml, intent_filter, manifest
from apkscan.apk import APK
from apkscan.axml import AXMLError, parse_axml
import deeplink_scanner
import tapjacking_scanner
import task_hijacking_scanner

VIEW = "android.intent.action.VIEW"
DEFAULT, BROWSABLE = "android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"
PKG = "com.example.app"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def apk(self, activities, min_sdk=24, target_sdk=34, app_attrs=None, permissions=None, extra=None):
        path = os.path.join(self.tmp.name, "t.apk")
        build_apk(path, manifest(PKG, min_sdk, target_sdk, activities, app_attrs, permissions), extra)
        return APK(path)

    def raw_apk(self, manifest_bytes, extra=None):
        path = os.path.join(self.tmp.name, "raw.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("AndroidManifest.xml", manifest_bytes)
            for name, data in (extra or {}).items():
                z.writestr(name, data)
        return path

    @staticmethod
    def names(findings):
        return [f.component for f in findings]

    @staticmethod
    def by_name(findings, name):
        return [f for f in findings if f.component.startswith(name)]


# --------------------------------------------------------------------------- #
# Parser robustness: a broken file must raise or degrade, never look "clean".
# --------------------------------------------------------------------------- #
class ParserRobustnessTests(Base):
    def test_garbage_axml_raises(self):
        for bad in (b"", b"\x03\x00\x08\x00\xff\xff\xff\xff", b"PK\x03\x04nope", b"\x00" * 64):
            with self.assertRaises(AXMLError):
                parse_axml(bad)

    def test_missing_manifest_raises(self):
        path = os.path.join(self.tmp.name, "nomani.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("classes.dex", b"dex\n035\x00")
        with self.assertRaises(Exception):
            APK(path)

    def test_no_resources_still_parses_manifest(self):
        path = self.raw_apk(build_axml(manifest(PKG, 24, 34,
                            [activity(".M", {"android:exported": True},
                                      [intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp"}])])])))
        apk = APK(path)
        self.assertEqual(len(apk.manifest.activities), 1)
        self.assertIsNone(apk.resources)
        # scanners must run and still see the exported deep link
        f, _ = deeplink_scanner.build_findings(apk, False, False)
        self.assertEqual(len(f), 1)

    def test_corrupt_resources_does_not_abort(self):
        extra = {"resources.arsc": b"\x02\x00\x0c\x00" + b"\xff" * 40}
        path = self.raw_apk(build_axml(manifest(PKG, 24, 34, [activity(".M", {"android:exported": True})])), extra)
        apk = APK(path)   # must not raise
        self.assertEqual(len(apk.manifest.activities), 1)

    def test_no_dex_scanners_do_not_crash(self):
        apk = self.apk([activity(".M", {"android:exported": True}, [LAUNCHER])])
        self.assertEqual(len(apk.dex.dexes), 0)
        self.assertTrue(tapjacking_scanner.build_findings(apk, False)[0])
        self.assertTrue(task_hijacking_scanner.build_findings(apk, False))

    def test_class_absent_is_reported_not_silently_safe(self):
        # No DEX, so the class cannot be found. A missing class must NOT read as mitigated.
        apk = self.apk([activity(".Main", {"android:exported": True}, [LAUNCHER])])
        f, _ = tapjacking_scanner.build_findings(apk, False)
        main = self.by_name(f, PKG + ".Main")[0]
        self.assertEqual(main.severity, "HIGH")
        self.assertTrue(any("class not found" in r for r in main.reasons))


# --------------------------------------------------------------------------- #
# AXML value handling.
# --------------------------------------------------------------------------- #
class AxmlValueTests(Base):
    def test_launch_mode_integer_resolves_to_name(self):
        for val, expect in ((0, "standard"), (2, "singleTask"), (3, "singleInstance"), (4, "singleInstancePerTask")):
            apk = self.apk([activity(".M", {"android:launchMode": val})])
            self.assertEqual(apk.manifest.activities[0].launch_mode, expect)

    def test_bool_as_literal_string(self):
        root = parse_axml(build_axml(("activity", {"android:exported": "true", "android:enabled": "false"}, [])))
        self.assertTrue(root.get_bool("exported"))
        self.assertFalse(root.get_bool("enabled"))

    def test_empty_vs_missing_task_affinity(self):
        apk = self.apk([activity(".A", {"android:taskAffinity": ""}), activity(".B")])
        self.assertEqual(apk.manifest.activities[0].task_affinity, "")      # explicitly empty
        self.assertIsNone(apk.manifest.activities[1].task_affinity)          # not set


# --------------------------------------------------------------------------- #
# Deep links: the filter must always be surfaced when exported.
# --------------------------------------------------------------------------- #
class DeeplinkCoverageTests(Base):
    def scan(self, acts, **kw):
        return deeplink_scanner.build_findings(self.apk(acts, **kw), kw.get("show_all", False), False)

    def test_data_merged_across_multiple_tags(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE],
                            [{"scheme": "https"}, {"host": "ex.com"}, {"pathPrefix": "/x"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertIn("https://ex.com/x<ANYTHING>", f[0].details["urls to test"])

    def test_scheme_specific_part(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "mailto", "ssp": "victim@x"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertEqual(len(f), 1)
        self.assertIn("mailto:victim@x", f[0].details["urls to test"])

    def test_mime_only_filter_reported(self):
        flt = intent_filter([VIEW], [DEFAULT], [{"mimeType": "application/pdf"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertEqual(len(f), 1)

    def test_every_web_url_host_missing_is_high(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertEqual(f[0].severity, "HIGH")

    def test_wildcard_host_flagged(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https", "host": "*.example.com"}], auto_verify=True)
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertTrue(any("wildcard host" in r for r in f[0].reasons))

    def test_pathpattern_catchall_flagged(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https", "host": "ex.com", "pathPattern": ".*"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertTrue(any("matches every path" in r for r in f[0].reasons))

    def test_mixed_web_and_custom_scheme(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https", "host": "h"}, {"scheme": "myapp", "host": "h"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        urls = f[0].details["urls to test"]
        self.assertTrue(any(u.startswith("https://") for u in urls))
        self.assertTrue(any(u.startswith("myapp://") for u in urls))

    def test_non_view_action_still_reported(self):
        flt = intent_filter(["com.custom.ACTION"], [DEFAULT], [{"scheme": "myapp", "host": "h"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertEqual(len(f), 1)

    def test_commands_emitted_for_each_url(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp", "host": "h"}])
        f, _ = self.scan([activity(".M", {"android:exported": True}, [flt])])
        self.assertTrue(f[0].commands)
        self.assertTrue(f[0].commands[0].startswith("adb shell am start"))

    def test_disabled_component_skipped(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp"}])
        f, _ = self.scan([activity(".Off", {"android:exported": True, "android:enabled": False}, [flt])])
        self.assertEqual(f, [])


# --------------------------------------------------------------------------- #
# Tapjacking: the no-UI note must not hide a real finding (regression).
# --------------------------------------------------------------------------- #
class TapjackingCoverageTests(Base):
    def scan(self, acts, **kw):
        return tapjacking_scanner.build_findings(self.apk(acts, min_sdk=kw.get("min_sdk", 24),
                                                          permissions=kw.get("permissions")), kw.get("show_all", False))

    def test_no_ui_does_not_downgrade_severity(self):
        # class absent (no dex) counts as "has_ui unknown"; severity must stay HIGH when exported.
        f, _ = self.scan([activity(".Main", {"android:exported": True}, [LAUNCHER])])
        self.assertEqual(self.by_name(f, PKG + ".Main")[0].severity, "HIGH")

    def test_hide_overlays_without_permission_not_counted(self):
        # setHideOverlayWindows referenced but no HIDE_OVERLAY_WINDOWS permission: still vulnerable.
        f, summary = self.scan([activity(".M", {"android:exported": True}, [LAUNCHER])])
        self.assertFalse(summary["hide_overlay_windows_permission"])
        self.assertEqual(self.by_name(f, PKG + ".M")[0].severity, "HIGH")

    def test_min_sdk_31_stays_high(self):
        f, summary = self.scan([activity(".Main", {"android:exported": True}, [LAUNCHER])], min_sdk=31)
        self.assertTrue(summary["all_devices_have_android12_touch_blocking"])
        self.assertEqual(self.by_name(f, PKG + ".Main")[0].severity, "HIGH")
        self.assertTrue(any("80% opacity" in r for r in self.by_name(f, PKG + ".Main")[0].reasons))

    def test_internal_activity_is_medium(self):
        f, _ = self.scan([activity(".Internal", {"android:exported": False})])
        self.assertEqual(self.by_name(f, PKG + ".Internal")[0].severity, "MEDIUM")


# --------------------------------------------------------------------------- #
# Task hijacking: routing-by-affinity cases must fire even when not exported.
# --------------------------------------------------------------------------- #
class TaskHijackCoverageTests(Base):
    def scan(self, acts, **kw):
        return task_hijacking_scanner.build_findings(self.apk(acts, min_sdk=kw.get("min_sdk", 24),
                                                              app_attrs=kw.get("app_attrs")), kw.get("show_all", False))

    def test_internal_single_task_is_high(self):
        # not exported, not launcher, but singleTask routes by affinity -> must be HIGH.
        f = self.scan([activity(".S", {"android:exported": False, "android:launchMode": "singleTask"})])
        self.assertEqual(f[0].severity, "HIGH")

    def test_single_instance_per_task_is_high(self):
        f = self.scan([activity(".S", {"android:exported": True, "android:launchMode": "singleInstancePerTask"})])
        self.assertEqual(f[0].severity, "HIGH")

    def test_single_instance_is_ok(self):
        f = self.scan([activity(".S", {"android:exported": True, "android:launchMode": "singleInstance"})])
        self.assertEqual(f[0].severity, "OK")

    def test_app_level_reparenting_inherited(self):
        f = self.scan([activity(".M", {"android:exported": True})], app_attrs={"android:allowTaskReparenting": True})
        self.assertEqual(f[0].severity, "HIGH")

    def test_custom_affinity_noted_public(self):
        f = self.scan([activity(".M", {"android:exported": True, "android:taskAffinity": "com.evil.shared"})])
        self.assertEqual(f[0].severity, "MEDIUM")
        self.assertTrue(any("public" in r for r in f[0].reasons))

    def test_min_sdk_30_downgrades_to_info(self):
        f = self.scan([activity(".Main", {"android:exported": True}, [LAUNCHER]),
                       activity(".S", {"android:launchMode": "singleTask"})], min_sdk=30)
        self.assertTrue(all(x.severity == "INFO" for x in f))


# --------------------------------------------------------------------------- #
# JSON output is well-formed for every scanner.
# --------------------------------------------------------------------------- #
class JsonOutputTests(Base):
    def test_json_round_trips(self):
        import io
        import json
        from contextlib import redirect_stdout

        path = os.path.join(self.tmp.name, "t.apk")
        build_apk(path, manifest(PKG, 24, 34,
                  [activity(".Main", {"android:exported": True, "android:launchMode": "singleTask"},
                            [LAUNCHER, intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp", "host": "oauth"}])])]))
        for mod in (tapjacking_scanner, deeplink_scanner, task_hijacking_scanner):
            buf = io.StringIO()
            with redirect_stdout(buf):
                mod.main([path, "--json"])
            data = json.loads(buf.getvalue())
            self.assertIn("findings", data)
            self.assertEqual(data["package"], PKG)


if __name__ == "__main__":
    unittest.main()


class SampleApkRegressionTests(unittest.TestCase):
    """Runs only when APKSCAN_SAMPLE points at a real .apk. Asserts the scanners
    parse it and return structurally sane findings, catching parser regressions."""

    def setUp(self):
        self.sample = os.environ.get("APKSCAN_SAMPLE")
        if not self.sample or not os.path.exists(self.sample):
            self.skipTest("set APKSCAN_SAMPLE=/path/to/app.apk to run")

    def test_parses_and_scans(self):
        apk = APK(self.sample)
        self.assertTrue(apk.manifest.package)
        self.assertIsNotNone(apk.manifest.min_sdk)
        # every scanner returns a list and every finding has a known severity
        tj, _ = tapjacking_scanner.build_findings(apk, True)
        dl, _ = deeplink_scanner.build_findings(apk, True, False)
        th = task_hijacking_scanner.build_findings(apk, True)
        for findings in (tj, dl, th):
            for f in findings:
                self.assertIn(f.severity, ("HIGH", "MEDIUM", "LOW", "INFO", "OK"))
                self.assertTrue(f.component and f.title)
