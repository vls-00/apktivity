#!/usr/bin/env python3
"""
Tapjacking scanner: lists activities that still accept touches while another app's
overlay covers them, and what (if anything) protects each one.

Checks View.setFilterTouchesWhenObscured / onFilterTouchEventForSecurity in the class
chain, filterTouchesWhenObscured in the inflated layouts, Window.setHideOverlayWindows
(API 31+, needs HIDE_OVERLAY_WINDOWS). The Android 12 untrusted-touch blocking is
mentioned for context only: it is bypassed by overlays at 80% opacity or less, so it
does not change the rating.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkscan.apk import api_label
from apkscan.axml import ANDROID_NS
from apkscan.report import (HIGH, INFO, LOW, MEDIUM, OK, Finding, Style, base_parser, emit_json, exit_code,
                            load_apk, print_findings, print_header, summary_line)

BLOCK_UNTRUSTED_TOUCHES_API = 31
HIDE_OVERLAY_WINDOWS_API = 31

M_HIDE_OVERLAYS = "->setHideOverlayWindows"
M_FILTER_TOUCHES = "->setFilterTouchesWhenObscured"
M_GET_FLAGS = "Landroid/view/MotionEvent;->getFlags"
M_OVERRIDE = "onFilterTouchEventForSecurity"
COMPOSE_SET_CONTENT = "Landroidx/activity/compose/ComponentActivityKt;->setContent"
# anything that suggests the activity actually draws something
UI_METHODS = ("->setContentView", "->addContentView", "->inflate", "->setContent", "->show",
              "Landroid/app/Dialog;-><init>", "->setView")

UI_FRAMEWORKS = {
    "Lio/flutter/embedding/android/FlutterActivity;": "Flutter",
    "Lio/flutter/embedding/android/FlutterFragmentActivity;": "Flutter",
    "Lio/flutter/app/FlutterActivity;": "Flutter",
    "Lcom/facebook/react/ReactActivity;": "React Native",
    "Lcom/getcapacitor/BridgeActivity;": "Capacitor (WebView)",
    "Lorg/apache/cordova/CordovaActivity;": "Cordova (WebView)",
    "Lcom/unity3d/player/UnityPlayerActivity;": "Unity",
    "Lcom/unity3d/player/UnityPlayerGameActivity;": "Unity",
    "Lorg/godotengine/godot/GodotActivity;": "Godot",
}
SENSITIVE_NAME = re.compile(r"login|signin|sign_in|auth|otp|pin|passw|pay|checkout|transfer|permission|consent|"
                            r"setting|admin|confirm|verify|biometric|2fa|mfa|wallet|card|bank|purchase|surequest|"
                            r"grant|approve", re.I)


class LayoutInfo:
    def __init__(self, res_id, name, path):
        self.res_id = res_id
        self.name = name
        self.path = path
        self.parsed = False
        self.root_protected = False
        self.protected_views = 0
        self.total_views = 0

    def label(self):
        if not self.parsed:
            return "%s (could not parse)" % self.name
        if self.root_protected:
            return "%s (root view has filterTouchesWhenObscured=true: protected)" % self.name
        if self.protected_views:
            return "%s (%d/%d views protected: partial)" % (self.name, self.protected_views, self.total_views)
        return "%s (no filterTouchesWhenObscured)" % self.name


def scan_layouts(apk):
    """res id -> LayoutInfo for every layout, with filterTouchesWhenObscured usage."""
    out = {}
    if not apk.resources:
        return out
    for rid, name in apk.resources.layout_ids().items():
        path = apk.layout_path(rid)
        info = out[rid] = LayoutInfo(rid, name, path)
        root = apk.parse_xml(path) if path else None
        if root is None:
            continue
        info.parsed = True
        for el in root.iter():
            info.total_views += 1
            tv = el.attr("filterTouchesWhenObscured", ANDROID_NS)
            val = el.get_bool("filterTouchesWhenObscured")
            if tv is not None and tv.is_reference():
                val = apk.resources.resolve_bool(tv.data)
            if val:
                info.protected_views += 1
                if el is root:
                    info.root_protected = True
    return out


def analyse_activity(apk, act, layouts):
    ev = {"class_found": False, "chain": [], "framework": None, "hide_overlays": [], "filter_touches": [],
          "get_flags": [], "override": [], "layouts": [], "compose": False, "ui": []}
    chain = apk.dex.superclass_chain(act.name)
    if not chain:
        return ev
    ev["class_found"] = True
    ev["chain"] = [c.name for c in chain]
    for c in chain:
        if c.name in UI_FRAMEWORKS:
            ev["framework"] = UI_FRAMEWORKS[c.name]

    classes = list(chain)
    for c in chain:
        classes.extend(apk.dex.inner_classes(c.name))
    for c in classes:
        invoked = c.invoked_methods()
        if any(m.endswith(M_HIDE_OVERLAYS) for m in invoked):
            ev["hide_overlays"].append(c.name)
        if any(m.endswith(M_FILTER_TOUCHES) for m in invoked):
            ev["filter_touches"].append(c.name)
        if M_GET_FLAGS in invoked:
            ev["get_flags"].append(c.name)
        if M_OVERRIDE in c.method_names():
            ev["override"].append(c.name)
        if COMPOSE_SET_CONTENT in invoked:
            ev["compose"] = True
        for m in invoked:
            if m.endswith(UI_METHODS) and m not in ev["ui"]:
                ev["ui"].append(m)
        for const in c.int_constants():
            if const in layouts and layouts[const] not in ev["layouts"]:
                ev["layouts"].append(layouts[const])
    return ev


def build_findings(apk, show_all):
    m = apk.manifest
    min_sdk = m.min_sdk or 1
    all_devices_api31 = min_sdk >= BLOCK_UNTRUSTED_TOUCHES_API
    layouts = scan_layouts(apk)
    protected_layouts = [l.name for l in layouts.values() if l.root_protected or l.protected_views]
    has_hide_perm = "android.permission.HIDE_OVERLAY_WINDOWS" in m.uses_permissions
    app_refs = {name: apk.dex.any_string_contains(name)
                for name in ("setHideOverlayWindows", "setFilterTouchesWhenObscured", "onFilterTouchEventForSecurity")}
    summary = {
        "all_devices_have_android12_touch_blocking": all_devices_api31,
        "android12_touch_blocking_bypassable": True,
        "hide_overlay_windows_permission": has_hide_perm,
        "dex_references": app_refs,
        "layouts_total": len(layouts),
        "layouts_with_filterTouchesWhenObscured": protected_layouts,
    }

    aliases_of = {}
    for c in m.activities:
        if c.kind == "activity-alias" and c.target_activity:
            aliases_of.setdefault(c.target_activity, []).append(c)

    findings = []
    for act in m.activities:
        if act.kind != "activity":
            continue
        if not act.is_enabled():
            if show_all:
                findings.append(Finding(INFO, act.name, "Activity is disabled in the manifest (android:enabled=false); skipped."))
            continue
        aliases = [a for a in aliases_of.get(act.name, []) if a.is_enabled()]
        exported = act.is_exported() or any(a.is_exported() for a in aliases)
        launcher = act.is_launcher() or any(a.is_launcher() for a in aliases)

        ev = analyse_activity(apk, act, layouts)
        reasons, fixes, details = [], [], {}

        details["exported"] = "%s (%s)" % ("yes" if exported else "no", act.exported_reason())
        if launcher:
            details["launcher"] = "yes (MAIN/LAUNCHER entry point)"
        if act.permission:
            details["permission"] = act.permission
        if aliases:
            details["aliases"] = ["%s (%s)" % (a.name, "exported" if a.is_exported() else "not exported") for a in aliases]
        if ev["framework"]:
            details["ui framework"] = ev["framework"]
        elif ev["compose"]:
            details["ui framework"] = "Jetpack Compose (setContent)"
        if ev["layouts"]:
            details["layouts inflated"] = [l.label() for l in ev["layouts"]]

        # what we found in terms of protection
        layout_full = bool(ev["layouts"]) and all(l.root_protected for l in ev["layouts"])
        layout_partial = not layout_full and any(l.root_protected or l.protected_views for l in ev["layouts"])
        hide_overlays = bool(ev["hide_overlays"]) and has_hide_perm
        manual_flags = bool(ev["get_flags"])
        evidence = []
        if ev["filter_touches"]:
            evidence.append("setFilterTouchesWhenObscured() called in " + ", ".join(map(_short, ev["filter_touches"])))
        if ev["override"]:
            evidence.append("onFilterTouchEventForSecurity() overridden in " + ", ".join(map(_short, ev["override"])))
        if layout_full:
            evidence.append("every inflated layout has filterTouchesWhenObscured=true on its root view")
        elif layout_partial:
            evidence.append("only some inflated layouts/views set filterTouchesWhenObscured")
        if ev["hide_overlays"]:
            note = "" if has_hide_perm else " BUT android.permission.HIDE_OVERLAY_WINDOWS is not declared, so it does nothing"
            evidence.append("Window.setHideOverlayWindows() called in " + ", ".join(map(_short, ev["hide_overlays"])) + note)
        if manual_flags:
            evidence.append("MotionEvent.getFlags() checked in %s (manual FLAG_WINDOW_IS_OBSCURED check? verify)"
                            % ", ".join(map(_short, ev["get_flags"])))
        if evidence:
            details["mitigation evidence"] = evidence
        if not ev["class_found"]:
            reasons.append("activity class not found in the APK's DEX files (split APK / dynamic feature?), "
                           "mitigations could not be checked")

        view_protected = bool(ev["filter_touches"] or ev["override"]) or layout_full

        if view_protected:
            severity = OK
            title = "Touch filtering when obscured is applied; tapjacking mitigated on all supported devices."
        elif hide_overlays and min_sdk >= HIDE_OVERLAY_WINDOWS_API:
            severity = OK
            title = "setHideOverlayWindows(true) hides untrusted overlays; mitigated on all supported devices (minSdk >= 31)."
        elif hide_overlays:
            severity = LOW if exported else INFO
            title = ("Mitigated only on Android 12+: setHideOverlayWindows() is a no-op below API 31, devices on %s .. API 30 "
                     "stay tapjackable." % api_label(min_sdk))
            reasons.append("no View-level filterTouchesWhenObscured protection found for pre-Android 12 devices")
        elif layout_partial or manual_flags:
            severity = MEDIUM if exported else LOW
            title = "Partial tapjacking protection: some views filter obscured touches, others do not."
            reasons.append("views without filterTouchesWhenObscured still receive touches while an overlay covers them")
        else:
            severity = HIGH if exported else MEDIUM
            title = "No tapjacking protection found: activity accepts touches while obscured by another app's overlay."
            reasons.append("no filterTouchesWhenObscured (code or layout), no onFilterTouchEventForSecurity override, "
                           "no effective setHideOverlayWindows in the activity or its superclasses")

        # We note when no UI could be found (likely a trampoline activity that finishes
        # immediately) but deliberately do NOT lower the severity: the UI may be set through
        # a path we do not follow (ViewBinding, a themed dialog, a superclass), and missing a
        # real tapjackable screen is worse than an extra finding to check by hand.
        has_ui = bool(ev["ui"] or ev["layouts"] or ev["compose"] or ev["framework"]) or not ev["class_found"]
        if severity != OK and not has_ui:
            details["note"] = ("no setContentView/inflate/Compose found in the class chain: may be a trampoline "
                               "activity with no UI, or UI set through a path this scanner does not follow (verify)")

        if severity != OK:
            if exported:
                reasons.append("exported: a malicious app can start this screen itself and cover it with an overlay right away")
            else:
                reasons.append("not exported: the attacker has to wait for the user to navigate here (overlay timed from a background service)")
            if all_devices_api31:
                reasons.append("minSdk %d >= 31: Android 12's untrusted-touch blocking is present on every supported device, but "
                               "it only drops touches through overlays above 80%% opacity; an overlay at 80%% or a hole over the "
                               "target still works, so the app needs its own protection" % min_sdk)
            else:
                reasons.append("minSdk %d < 31: devices on %s .. API 30 have no platform untrusted-touch blocking at all, and "
                               "the Android 12+ blocking is bypassed with overlays at 80%% opacity or less anyway"
                               % (min_sdk, api_label(min_sdk)))
            if ev["framework"]:
                reasons.append("UI is rendered by %s: per-view XML attributes do not apply, protect the framework's root view "
                               "or the Window instead" % ev["framework"])
            if SENSITIVE_NAME.search(act.short_name):
                reasons.append("name suggests a sensitive screen (auth/payment/permission style), a prime tapjacking target")
            if not evidence and any(app_refs.values()):
                reasons.append("the app does reference mitigation APIs somewhere else (custom views?); run --deep to list "
                               "those classes and check coverage by hand")
            fixes.append('set android:filterTouchesWhenObscured="true" on the root view of each layout (or call '
                         "setFilterTouchesWhenObscured(true) on the content view) of sensitive screens")
            fixes.append("on Android 12+: declare android.permission.HIDE_OVERLAY_WINDOWS and call "
                         "getWindow().setHideOverlayWindows(true) in onCreate()")

        if ev["class_found"]:
            details["class chain"] = " > ".join(map(_short, ev["chain"][:4])) + (" > ..." if len(ev["chain"]) > 4 else "")
        commands = []
        if exported and severity != OK:
            commands.append("adb shell am start -n %s/%s" % (m.package, act.name))
        findings.append(Finding(severity, act.name, title, reasons, fixes, details, commands))

    return findings, summary


def _short(desc):
    return desc[1:-1].replace("/", ".") if desc.startswith("L") and desc.endswith(";") else desc


def main(argv=None):
    p = base_parser(__doc__)
    p.add_argument("--deep", action="store_true",
                   help="walk every class in the DEX and list the ones calling anti-tapjacking APIs (slower)")
    args = p.parse_args(argv)
    apk = load_apk(args)
    findings, summary = build_findings(apk, args.all)

    deep = {}
    if args.deep:
        for api in (M_HIDE_OVERLAYS, M_FILTER_TOUCHES, M_GET_FLAGS):
            deep[api.split("->")[-1]] = [_short(c) for c in apk.dex.classes_invoking(api)]

    if args.json:
        emit_json(apk, "tapjacking", findings, {"app": summary, "deep": deep or None})
        return exit_code(findings)

    m = apk.manifest
    protected = summary["layouts_with_filterTouchesWhenObscured"]
    layouts_line = "Layouts: %d total, %d use filterTouchesWhenObscured" % (summary["layouts_total"], len(protected))
    if protected:
        layouts_line += ": " + ", ".join(protected[:8]) + (" ..." if len(protected) > 8 else "")
    print_header(apk, "Tapjacking scanner", [
        "Android 12 untrusted-touch blocking: %s; bypassable with overlays at <= 80%% opacity, not counted as a mitigation"
        % ("on all supported devices (minSdk >= 31)" if summary["all_devices_have_android12_touch_blocking"]
           else "only on devices >= API 31 (minSdk %d)" % (m.min_sdk or 1)),
        "HIDE_OVERLAY_WINDOWS permission declared: %s" % ("yes" if summary["hide_overlay_windows_permission"] else "no"),
        "DEX references: " + ", ".join("%s=%s" % (k, "yes" if v else "no") for k, v in summary["dex_references"].items()),
        layouts_line,
    ])
    print_findings(findings, args.all)
    if deep:
        print(Style.bold("Classes calling anti-tapjacking APIs (--deep):"))
        for k, v in deep.items():
            print("  %s: %s" % (k, ", ".join(v) if v else "-"))
        print()
    print(summary_line(findings))
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
