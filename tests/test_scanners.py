import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from axml_writer import LAUNCHER, activity, build_apk, build_axml, intent_filter, manifest
from apkscan.apk import APK
from apkscan.axml import parse_axml
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

    def apk(self, activities, min_sdk=24, target_sdk=34, app_attrs=None, permissions=None, extra=None) -> APK:
        path = os.path.join(self.tmp.name, "t.apk")
        build_apk(path, manifest(PKG, min_sdk, target_sdk, activities, app_attrs, permissions), extra)
        return APK(path)

    @staticmethod
    def by_name(findings, name):
        return [f for f in findings if f.component.startswith(name)]


class ParserTests(Base):
    def test_manifest_roundtrip(self):
        apk = self.apk([activity(".Main", {"android:exported": True, "android:launchMode": "singleTask",
                                           "android:taskAffinity": ""}, [LAUNCHER])], min_sdk=21, target_sdk=33)
        m = apk.manifest
        self.assertEqual(m.package, PKG)
        self.assertEqual((m.min_sdk, m.target_sdk), (21, 33))
        a = m.activities[0]
        self.assertEqual(a.name, PKG + ".Main")
        self.assertTrue(a.exported_attr)
        self.assertEqual(a.launch_mode, "singleTask")
        self.assertEqual(a.task_affinity, "")
        self.assertTrue(a.is_launcher())

    def test_layout_attribute(self):
        xml = build_axml(("LinearLayout", {"android:filterTouchesWhenObscured": True},
                          [("Button", {"android:filterTouchesWhenObscured": False}, [])]))
        root = parse_axml(xml)
        self.assertTrue(root.get_bool("filterTouchesWhenObscured"))
        self.assertFalse(root.children[0].get_bool("filterTouchesWhenObscured"))

    def test_relative_names_and_default_export(self):
        apk = self.apk([activity("Plain"), activity(".WithFilter", {}, [intent_filter([VIEW], [DEFAULT])]),
                        activity("com.other.Full", {"android:exported": False}, [intent_filter([VIEW], [DEFAULT])])])
        a, b, c = apk.manifest.activities
        self.assertEqual(a.name, PKG + ".Plain")
        self.assertFalse(a.is_exported(34))
        self.assertTrue(b.is_exported(34))       # implicit via intent-filter
        self.assertFalse(c.is_exported(34))      # explicit false wins


class TaskHijackingTests(Base):
    def run_scan(self, acts, min_sdk=24, show_all=False, app_attrs=None):
        return task_hijacking_scanner.build_findings(self.apk(acts, min_sdk=min_sdk, app_attrs=app_attrs), show_all)

    def test_launcher_default_affinity_is_high(self):
        f = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER])])
        self.assertEqual(f[0].severity, "HIGH")
        self.assertIn("StrandHogg", f[0].title)

    def test_single_task_and_reparenting(self):
        f = self.run_scan([activity(".A", {"android:exported": False, "android:launchMode": "singleTask"}),
                           activity(".B", {"android:exported": False, "android:allowTaskReparenting": True})])
        self.assertEqual([x.severity for x in f], ["HIGH", "HIGH"])

    def test_exported_standard_is_medium_and_internal_hidden(self):
        f = self.run_scan([activity(".Exp", {"android:exported": True}), activity(".Internal")])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "MEDIUM")
        f = self.run_scan([activity(".Exp", {"android:exported": True}), activity(".Internal")], show_all=True)
        self.assertEqual(self.by_name(f, PKG + ".Internal")[0].severity, "INFO")

    def test_safe_configurations(self):
        f = self.run_scan([activity(".Main", {"android:exported": True, "android:taskAffinity": ""}, [LAUNCHER]),
                           activity(".Solo", {"android:exported": True, "android:launchMode": "singleInstance"})])
        self.assertEqual([x.severity for x in f], ["OK", "OK"])

    def test_application_level_affinity(self):
        f = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER])], app_attrs={"android:taskAffinity": ""})
        self.assertEqual(f[0].severity, "OK")
        f = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER])], app_attrs={"android:taskAffinity": "shared.aff"})
        self.assertEqual(f[0].severity, "HIGH")
        self.assertTrue(any("custom affinity" in r for r in f[0].reasons))

    def test_alias_launcher_counts_for_target(self):
        f = self.run_scan([activity(".Main", {"android:exported": False}),
                           activity(".Alias", {"android:exported": True, "android:targetActivity": ".Main"}, [LAUNCHER], tag="activity-alias")])
        self.assertEqual(f[0].component, PKG + ".Main")
        self.assertEqual(f[0].severity, "HIGH")

    def test_min_sdk_30_is_informational(self):
        f = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER]),
                           activity(".S", {"android:launchMode": "singleTask"})], min_sdk=30)
        self.assertEqual([x.severity for x in f], ["INFO", "INFO"])
        self.assertTrue(any("Android 11 fix" in r for r in f[0].reasons))


class DeeplinkTests(Base):
    def run_scan(self, acts, min_sdk=24, target_sdk=34, show_all=False):
        return deeplink_scanner.build_findings(self.apk(acts, min_sdk=min_sdk, target_sdk=target_sdk), show_all, False)

    def test_url_expansion(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE],
                            [{"scheme": "https"}, {"scheme": "http"}, {"host": "example.com"}, {"host": "*.example.org", "port": "8443"},
                             {"pathPrefix": "/app"}, {"path": "/exact"}], auto_verify=False)
        f, _ = self.run_scan([activity(".Main", {"android:exported": True}, [flt])])
        urls = f[0].details["urls to test"]
        self.assertIn("https://example.com/app<ANYTHING>", urls)
        self.assertIn("http://*.example.org:8443/exact", urls)
        self.assertEqual(len(urls), 8)
        self.assertTrue(any("wildcard host" in r for r in f[0].reasons))

    def test_custom_scheme_medium_auth_high(self):
        f, _ = self.run_scan([activity(".A", {"android:exported": True}, [intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp", "host": "home"}])]),
                              activity(".B", {"android:exported": True}, [intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp", "host": "oauth"}])])])
        self.assertEqual(self.by_name(f, PKG + ".A")[0].severity, "MEDIUM")
        self.assertEqual(self.by_name(f, PKG + ".B")[0].severity, "HIGH")

    def test_https_without_autoverify_depends_on_sdk(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https", "host": "example.com"}])
        f, _ = self.run_scan([activity(".M", {"android:exported": True}, [flt])], min_sdk=24, target_sdk=34)
        self.assertEqual(f[0].severity, "MEDIUM")
        f, _ = self.run_scan([activity(".M", {"android:exported": True}, [flt])], min_sdk=31, target_sdk=34)
        self.assertEqual(f[0].severity, "LOW")
        self.assertTrue(any("opens in the browser" in r for r in f[0].reasons))

    def test_autoverify_collects_hosts_and_missing_host_is_high(self):
        ok = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https", "host": "a.example.com"}], auto_verify=True)
        bad = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "https"}])
        f, hosts = self.run_scan([activity(".M", {"android:exported": True}, [ok, bad])])
        self.assertIn("a.example.com", hosts)
        self.assertEqual(f[0].severity, "LOW")
        self.assertEqual(f[1].severity, "HIGH")
        self.assertIn("https://<ANY-HOST>/<ANY-PATH>", f[1].details["urls to test"])

    def test_not_exported_and_modifiers(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp"}])
        f, _ = self.run_scan([activity(".Hidden", {"android:exported": False}, [flt])])
        self.assertEqual(f, [])
        f, _ = self.run_scan([activity(".Hidden", {"android:exported": False}, [flt])], show_all=True)
        self.assertEqual(f[0].severity, "INFO")
        nodefault = intent_filter([VIEW], [BROWSABLE], [{"scheme": "myapp"}])
        f, _ = self.run_scan([activity(".ND", {"android:exported": True}, [nodefault])])
        self.assertEqual(f[0].severity, "LOW")  # downgraded from MEDIUM
        f, _ = self.run_scan([activity(".P", {"android:exported": True, "android:permission": "com.example.SECRET"}, [flt])])
        self.assertEqual(f[0].severity, "LOW")

    def test_alias_reported_with_target(self):
        flt = intent_filter([VIEW], [DEFAULT, BROWSABLE], [{"scheme": "myapp"}])
        f, _ = self.run_scan([activity(".Target", {"android:exported": False}),
                              activity(".Alias", {"android:exported": True, "android:targetActivity": ".Target"}, [flt], tag="activity-alias")])
        self.assertIn("alias -> " + PKG + ".Target", f[0].component)


class TapjackingTests(Base):
    def run_scan(self, acts, min_sdk=24, show_all=False, permissions=None):
        return tapjacking_scanner.build_findings(self.apk(acts, min_sdk=min_sdk, permissions=permissions), show_all)

    def test_exported_high_internal_medium(self):
        f, summary = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER]), activity(".Internal")])
        self.assertEqual(self.by_name(f, PKG + ".Main")[0].severity, "HIGH")
        self.assertEqual(self.by_name(f, PKG + ".Internal")[0].severity, "MEDIUM")
        self.assertFalse(summary["all_devices_have_android12_touch_blocking"])
        self.assertTrue(any("class not found" in r for r in f[0].reasons))

    def test_min_sdk_31_does_not_downgrade(self):
        f, summary = self.run_scan([activity(".Main", {"android:exported": True}, [LAUNCHER]), activity(".Internal")], min_sdk=31)
        self.assertTrue(summary["all_devices_have_android12_touch_blocking"])
        self.assertEqual(self.by_name(f, PKG + ".Main")[0].severity, "HIGH")
        self.assertEqual(self.by_name(f, PKG + ".Internal")[0].severity, "MEDIUM")
        self.assertTrue(any("80% opacity" in r for r in f[0].reasons))

    def test_disabled_skipped_and_permission_flag(self):
        f, summary = self.run_scan([activity(".Off", {"android:enabled": False, "android:exported": True})],
                                   permissions=["android.permission.HIDE_OVERLAY_WINDOWS"])
        self.assertEqual(f, [])
        self.assertTrue(summary["hide_overlay_windows_permission"])

    def test_alias_exports_target(self):
        f, _ = self.run_scan([activity(".Target", {"android:exported": False}),
                              activity(".Alias", {"android:exported": True, "android:targetActivity": ".Target"}, [LAUNCHER], tag="activity-alias")])
        t = self.by_name(f, PKG + ".Target")[0]
        self.assertEqual(t.severity, "HIGH")
        self.assertEqual(t.details.get("launcher"), "yes (MAIN/LAUNCHER entry point)")


if __name__ == "__main__":
    unittest.main()
