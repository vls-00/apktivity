#!/usr/bin/env python3
"""
Deep link scanner: expands every exported intent-filter into the URLs the app will
accept and says why each one is worth testing.

Custom schemes can be hijacked by any app; http/https without autoVerify gets a
chooser below Android 12 and opens in the browser from Android 12 (API 31) on, so
minSdk/targetSdk decide how exposed it really is; missing hosts or paths widen
the match; and the handler class is checked for URI reads, WebView loads and
intent redirection sinks.
"""
import json
import os
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkscan.apk import api_label
from apkscan.report import (HIGH, INFO, LOW, MEDIUM, OK, Finding, Style, base_parser, emit_json, exit_code,
                            load_apk, print_findings, print_header, summary_line)

WEB_INTENT_BROWSER_API = 31
WEB_SCHEMES = ("http", "https")
AUTH_HINT = re.compile(r"oauth|callback|login|auth|token|sso|signin|sign-in|verify|reset|magic|otp|session|redirect", re.I)

# method ref -> (label, explanation)
CODE_HINTS = {
    "Landroid/content/Intent;->getData": ("reads intent URI", "getIntent().getData() is used: URI content flows into the app"),
    "Landroid/content/Intent;->getDataString": ("reads intent URI", "getDataString() is used: URI content flows into the app"),
    "Landroid/net/Uri;->getQueryParameter": ("parses query params", "Uri.getQueryParameter(): attacker controlled query values are consumed"),
    "Landroid/net/Uri;->getQueryParameters": ("parses query params", "Uri.getQueryParameters(): attacker controlled query values are consumed"),
    "Landroid/net/Uri;->getQueryParameterNames": ("parses query params", "query parameter names are enumerated"),
    "Landroid/net/Uri;->getPathSegments": ("parses path", "path segments are consumed"),
    "Landroid/webkit/WebView;->loadUrl": ("WebView.loadUrl", "a WebView loads a URL: make sure deep link data cannot choose it (phishing, token theft, file:// access)"),
    "Landroid/webkit/WebView;->loadDataWithBaseURL": ("WebView.loadDataWithBaseURL", "HTML is rendered in a WebView with a base URL"),
    "Landroid/webkit/WebView;->postUrl": ("WebView.postUrl", "a WebView posts to a URL"),
    "Landroid/webkit/WebView;->evaluateJavascript": ("evaluateJavascript", "JavaScript is executed inside a WebView"),
    "Landroid/webkit/WebView;->addJavascriptInterface": ("JS bridge", "addJavascriptInterface(): a JavaScript bridge is exposed to loaded pages"),
    "Landroid/webkit/WebSettings;->setJavaScriptEnabled": ("JS enabled", "JavaScript is enabled in a WebView"),
    "Landroid/webkit/WebSettings;->setAllowFileAccess": ("file access", "WebView file access setting is touched"),
    "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs": ("universal file access", "setAllowUniversalAccessFromFileURLs(): dangerous if file:// content can be loaded"),
    "Landroid/content/Intent;->parseUri": ("Intent.parseUri", "Intent.parseUri(): an intent is built from a URI (intent:// scheme), the classic intent redirection sink"),
    "Landroid/content/Intent;->getParcelableExtra": ("reads Parcelable extra", "getParcelableExtra(): an embedded Intent/object is read from the caller"),
    "Landroid/content/Intent;->getStringExtra": ("reads extras", "string extras from the caller are processed"),
    "Landroid/content/Intent;->getExtras": ("reads extras", "the extras bundle from the caller is processed"),
    "Landroid/content/Context;->startActivity": ("startActivity", "starts another activity: intent redirection if target/extras come from the link"),
    "Landroid/app/Activity;->startActivity": ("startActivity", "starts another activity: intent redirection if target/extras come from the link"),
    "Landroid/app/Activity;->startActivityForResult": ("startActivityForResult", "starts another activity for result"),
    "Landroid/app/Activity;->setResult": ("setResult", "returns data to the caller, which may be a malicious app"),
    "Landroid/content/Context;->sendBroadcast": ("sendBroadcast", "broadcasts something derived from the intent"),
    "Landroid/content/Context;->startService": ("startService", "starts a service with caller data"),
}
FRAMEWORK_HANDLERS = {
    "Lio/flutter/embedding/android/FlutterActivity;": "Flutter: the link is forwarded to Dart (check the Dart router / uni_links / app_links handling)",
    "Lio/flutter/embedding/android/FlutterFragmentActivity;": "Flutter: the link is forwarded to Dart",
    "Lcom/facebook/react/ReactActivity;": "React Native: the link is forwarded to JS (Linking API)",
    "Lcom/getcapacitor/BridgeActivity;": "Capacitor: the link is forwarded to the web app (appUrlOpen event)",
    "Lorg/apache/cordova/CordovaActivity;": "Cordova: the link is forwarded to the web app",
    "Lcom/unity3d/player/UnityPlayerActivity;": "Unity: the link is handled by the Unity runtime",
}

_ORDER = [OK, INFO, LOW, MEDIUM, HIGH]


def max_sev(a, b):
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def downgrade(s):
    return {HIGH: MEDIUM, MEDIUM: LOW, LOW: INFO}.get(s, s)


def expand_urls(f):
    """(url patterns, structural notes) for one intent filter"""
    urls, notes = [], []
    schemes, auths, paths = f.schemes(), f.authorities(), f.paths()
    if not schemes:
        if auths or paths:
            notes.append("host/path given without android:scheme: Android ignores them, the filter cannot match URIs")
        return urls, notes
    if paths and not auths:
        notes.append("paths given without a host: path rules are ignored unless an authority is declared too")

    ssps = f.ssps()
    for s in schemes:
        if ssps and not auths:
            # scheme-specific-part filters (mailto:, tel:, sms:, custom opaque URIs) have no host
            for kind, val in ssps:
                if kind == "ssp":
                    urls.append("%s:%s" % (s, val))
                elif kind == "sspPrefix":
                    urls.append("%s:%s<ANYTHING>" % (s, val))
                else:
                    urls.append("%s:%s   [%s]" % (s, val, kind))
            continue
        if not auths:
            if s in WEB_SCHEMES:
                urls.append("%s://<ANY-HOST>/<ANY-PATH>" % s)
                notes.append("%s: no android:host, so EVERY %s URL matches this filter (and it cannot be verified)" % (s, s))
            else:
                urls.append("%s://<ANYTHING>" % s)
            continue
        for host, port in auths:
            base = "%s://%s%s" % (s, host, ":" + port if port else "")
            if not paths:
                urls.append(base + "/<ANY-PATH>")
                continue
            for kind, p in paths:
                if kind == "path":
                    urls.append(base + p)
                elif kind == "pathPrefix":
                    urls.append(base + p + "<ANYTHING>")
                elif kind == "pathSuffix":
                    urls.append(base + "<ANYTHING>" + p)
                else:
                    urls.append("%s%s   [%s]" % (base, p, kind))

    for host, _ in auths:
        if host.startswith("*"):
            notes.append("wildcard host %s: every subdomain matches, including ones an attacker may control (staging, user content)" % host)
    if auths and not paths:
        notes.append("no path restriction: every path on the host(s) is routed into the app")
    for kind, p in paths:
        if kind == "pathPrefix" and p in ("/", ""):
            notes.append('pathPrefix="/" matches every path')
        if kind in ("pathPattern", "pathAdvancedPattern") and (p in (".*", "/.*") or p.startswith(".*")):
            notes.append('%s="%s" matches every path' % (kind, p))
    return urls, notes


def code_hints(apk, class_name):
    """(hints, framework note, string literals) for the handler class"""
    chain = apk.dex.superclass_chain(class_name)
    if not chain:
        return ["handler class not found in DEX (split APK?)"], None, []
    framework = next((FRAMEWORK_HANDLERS[c.name] for c in chain if c.name in FRAMEWORK_HANDLERS), None)

    # the activity, its first two in-app superclasses and their inner classes; deeper
    # bases are usually AppCompat plumbing and only add noise
    classes = chain[:3]
    for c in chain:
        classes.extend(apk.dex.inner_classes(c.name))

    found = {}
    strings = []
    for c in classes:
        for ref in c.invoked_methods():
            for needle, (label, text) in CODE_HINTS.items():
                cls, meth = needle.split(";->")
                if ref == needle or (ref.endswith("->" + meth) and cls in ref):
                    found[label] = text
        if c is chain[0] or c not in chain:
            strings.extend(sorted(c.string_constants()))

    hints = list(found.values())
    if "WebView.loadUrl" in found and ("reads intent URI" in found or "parses query params" in found):
        hints.insert(0, "URI data AND WebView.loadUrl() in the same handler: strong candidate for arbitrary URL loading (open redirect / token theft)")
    if "Intent.parseUri" in found or ("reads Parcelable extra" in found and "startActivity" in found):
        hints.insert(0, "embedded intent is read and re-launched: check for intent redirection to non-exported components")
    return hints, framework, strings


def build_findings(apk, show_all, want_strings):
    m = apk.manifest
    min_sdk = m.min_sdk or 1
    target_sdk = m.effective_target() or 1
    browser_everywhere = min_sdk >= WEB_INTENT_BROWSER_API and target_sdk >= WEB_INTENT_BROWSER_API
    app_has_autoverify = any(f.auto_verify for a in m.activities for f in a.intent_filters)

    findings = []
    verify_hosts = {}      # host -> {"filters": [...]}, for --check-assetlinks
    url_owner = {}
    hint_cache = {}

    for comp in m.activities:
        if not comp.is_enabled():
            continue
        exported = comp.is_exported()
        is_alias = comp.kind == "activity-alias" and comp.target_activity
        handler = comp.target_activity if is_alias else comp.name
        label = "%s (alias -> %s)" % (comp.name, handler) if is_alias else comp.name
        target = m.activity(handler) if is_alias else comp
        permission = comp.permission or (target.permission if target else None)

        for idx, f in enumerate(comp.intent_filters, 1):
            urls, notes = expand_urls(f)
            mime_only = not f.schemes() and f.mime_types()
            if not urls and not mime_only:
                continue
            if not exported:
                if show_all:
                    findings.append(Finding(INFO, label, "intent-filter #%d declares data but the component is not exported: "
                                            "not reachable from other apps or the browser." % idx,
                                            details={"urls": urls, "actions": f.actions, "categories": f.categories}))
                continue

            reasons = list(notes)
            fixes = []
            details = {}
            severity = LOW
            schemes = f.schemes()
            custom = [s for s in schemes if s not in WEB_SCHEMES]
            web = [s for s in schemes if s in WEB_SCHEMES]

            details["urls to test"] = urls or ["(MIME only) " + ", ".join(f.mime_types())]
            details["actions"] = f.actions
            details["categories"] = f.categories
            if f.mime_types() and schemes:
                details["mime types"] = f.mime_types()
            details["autoVerify"] = "true" if f.auto_verify else "false"
            details["exported"] = comp.exported_reason()
            if permission:
                details["permission"] = permission

            if custom:
                severity = MEDIUM
                reasons.append("custom scheme(s) %s: schemes cannot be verified, any other installed app can declare the same "
                               "filter and receive the link (link hijacking)" % ", ".join(custom))
                if any(AUTH_HINT.search(u) for u in urls):
                    severity = HIGH
                    reasons.append("URL looks like an auth/callback/token flow: hijacking it leaks codes, tokens or session data")
                fixes.append("move auth/session links to verified https App Links (android:autoVerify), treat custom-scheme "
                             "input as untrusted, use PKCE so a stolen OAuth code is useless")

            if web:
                if f.auto_verify:
                    reasons.append("http/https with autoVerify: an App Link. Only safe if /.well-known/assetlinks.json on every "
                                   "host lists this package and its signing cert (run with --check-assetlinks)")
                    for host, _ in f.authorities():
                        h = host.lstrip("*.")
                        if h:
                            verify_hosts.setdefault(h, {"filters": []})["filters"].append(label)
                    if not f.authorities():
                        severity = max_sev(severity, MEDIUM)
                        reasons.append("autoVerify without a host can never be verified: on Android 12+ these links open in the "
                                       "browser, below 12 the chooser appears")
                    if "http" in web:
                        reasons.append("plain http is accepted too: a network attacker can rewrite the link and its parameters "
                                       "before it reaches the app")
                else:
                    if browser_everywhere:
                        severity = max_sev(severity, LOW)
                        reasons.append("https/http without autoVerify, minSdk %d and targetSdk %d >= 31: on every supported device "
                                       "a web link for this host opens in the browser instead of the app (Android 12 web intent "
                                       "resolution). Other apps can still send an explicit intent with this URL, and the user "
                                       "can enable the link by hand under 'Open by default'" % (min_sdk, target_sdk))
                    else:
                        severity = max_sev(severity, MEDIUM)
                        reasons.append("https/http without autoVerify: on devices running %s .. API 30 any app declaring the same "
                                       "host shows up in the chooser next to this one (or gets the link outright if the user "
                                       "picked 'always'), which enables phishing; on Android 12+ the link opens in the browser "
                                       "unless the user enables it manually" % api_label(min_sdk))
                        if target_sdk < WEB_INTENT_BROWSER_API:
                            reasons.append("targetSdk %d < 31: the Android 12 browser-first behaviour does not apply, the chooser "
                                           "behaviour stays on all devices" % target_sdk)
                    if app_has_autoverify:
                        reasons.append("another filter in this app uses autoVerify: below Android 12 verification is all-or-nothing, "
                                       "so this unverified host can make ALL App Links of the app fail")
                    fixes.append('add android:autoVerify="true" and publish /.well-known/assetlinks.json for each host')
                    if not f.authorities():
                        severity = max_sev(severity, HIGH)

            if mime_only:
                severity = INFO if severity == LOW else severity
                reasons.append("MIME-type filter (%s) without scheme: matches content:// and file:// URIs handed over by other "
                               "apps, validate the received stream" % ", ".join(f.mime_types()))

            if not f.has_category("DEFAULT"):
                reasons.append("no android.intent.category.DEFAULT: implicit VIEW intents (browser, other apps) will NOT match, "
                               "only explicit intents naming the component reach it (severity reduced)")
                severity = downgrade(severity)
            if not f.is_browsable():
                reasons.append("no BROWSABLE category: web pages/browsers cannot launch it, any installed app still can")
            if permission:
                reasons.append("protected by permission %s: only callers holding it can start the activity (severity reduced)" % permission)
                severity = downgrade(severity)
            if schemes and not f.has_action("VIEW"):
                reasons.append("non-VIEW action(s) %s: browsers send ACTION_VIEW, so this is reachable from apps only" % (", ".join(f.actions) or "-"))

            if handler not in hint_cache:
                hint_cache[handler] = code_hints(apk, handler)
            hints, framework, strings = hint_cache[handler]
            if framework:
                details["handler"] = framework
            if hints:
                details["code hints (handler class)"] = hints
                if any("strong candidate" in h or "intent redirection" in h for h in hints):
                    severity = max_sev(severity, HIGH)
            if want_strings and strings:
                details["string literals in handler"] = strings[:80] + (["..."] if len(strings) > 80 else [])

            for u in urls:
                url_owner.setdefault(u, []).append(label)
            commands = []
            for u in urls[:5]:
                clean = re.sub(r"<[^>]+>|\s+\[.*\]$", "", u)
                commands.append('adb shell am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE '
                                '-d "%s" %s' % (clean, m.package))
            if len(urls) > 5:
                commands.append("... %d more, see the URL list above" % (len(urls) - 5))
            fixes.append("validate scheme, host and every parameter of the incoming URI before using it; never load it into a "
                         "WebView or forward embedded intents unchecked")

            title = "intent-filter #%d at manifest line %d: %d URL pattern(s) exposed" % (idx, f.line, len(urls) or len(f.mime_types()))
            findings.append(Finding(severity, label, title, reasons, fixes, details, commands))

    for u, owners in url_owner.items():
        if len(set(owners)) > 1:
            findings.append(Finding(INFO, "multiple components", "%s is claimed by several components: %s. Android picks by "
                            "priority/order; both handlers need to validate input." % (u, ", ".join(sorted(set(owners))))))
    return findings, verify_hosts


def check_assetlinks(apk, hosts, timeout=10.0):
    """Fetch assetlinks.json per host and compare package name + cert fingerprint with the APK."""
    pkg = apk.manifest.package
    fps = apk.signing_cert_sha256()
    ctx = ssl.create_default_context()
    results = {}
    for host in sorted(hosts):
        url = "https://%s/.well-known/assetlinks.json" % host
        res = results[host] = {"url": url, "status": "ERROR", "detail": ""}
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "apk-deeplink-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                data = json.loads(r.read(512 * 1024))
            entries = [e for e in data if isinstance(e, dict)
                       and "delegate_permission/common.handle_all_urls" in e.get("relation", [])
                       and e.get("target", {}).get("namespace") == "android_app"]
            mine = [e for e in entries if e.get("target", {}).get("package_name") == pkg]
            if not mine:
                res["status"] = "PACKAGE NOT LISTED"
                res["detail"] = "listed packages: %s" % (sorted({e["target"].get("package_name") for e in entries}) or "none")
                continue
            listed = {fp.upper() for e in mine for fp in e["target"].get("sha256_cert_fingerprints", [])}
            if not fps:
                res["status"] = "PACKAGE OK, CERT UNKNOWN"
                res["detail"] = "could not extract APK certificate; site lists %s" % sorted(listed)
            elif listed & set(fps):
                res["status"] = "VERIFIED"
                res["detail"] = "package name and signing certificate match"
            else:
                res["status"] = "FINGERPRINT MISMATCH"
                res["detail"] = "APK certs %s not in %s (re-signed / different build?)" % (fps, sorted(listed))
        except Exception as e:
            res["detail"] = "%s: %s" % (type(e).__name__, e)
    return results


def main(argv=None):
    p = base_parser(__doc__)
    p.add_argument("--check-assetlinks", action="store_true",
                   help="fetch https://<host>/.well-known/assetlinks.json for autoVerify hosts and compare package + cert (network)")
    p.add_argument("--strings", action="store_true", help="dump string literals of each handler class (parameter names, paths)")
    args = p.parse_args(argv)
    apk = load_apk(args)
    findings, hosts = build_findings(apk, args.all, args.strings)

    verification = check_assetlinks(apk, hosts) if args.check_assetlinks and hosts else {}
    for host, res in verification.items():
        if res["status"] == "VERIFIED":
            continue
        for f in findings:
            if f.details.get("autoVerify") == "true" and any(host in u for u in f.details.get("urls to test", [])):
                if res["status"] != "ERROR":
                    f.severity = max_sev(f.severity, MEDIUM)
                f.reasons.append("assetlinks check for %s: %s (%s); an unverified App Link behaves like a plain https filter "
                                 "(chooser below Android 12, browser on 12+)" % (host, res["status"], res["detail"]))

    if args.json:
        emit_json(apk, "deeplink", findings, {"assetlinks": verification, "signing_cert_sha256": apk.signing_cert_sha256()})
        return exit_code(findings)

    m = apk.manifest
    browser = (m.min_sdk or 1) >= 31 and (m.effective_target() or 1) >= 31
    print_header(apk, "Deep link scanner", [
        "Unverified web links open in browser on all devices: "
        + ("yes (minSdk and targetSdk >= 31)" if browser else "no (devices below API 31 show the chooser)"),
        "Signing cert SHA-256: " + (", ".join(apk.signing_cert_sha256()) or "unknown"),
    ])
    print_findings(findings, args.all)
    if verification:
        print(Style.bold("Digital Asset Links verification:"))
        for host, res in verification.items():
            print("  %s: %s  %s" % (host, res["status"], res["detail"]))
        print()
    elif hosts:
        print(Style.dim("autoVerify hosts not checked (use --check-assetlinks): " + ", ".join(sorted(hosts))))
        print()
    print(summary_line(findings))
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
