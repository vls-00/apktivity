#!/usr/bin/env python3
"""
Task hijacking (StrandHogg) scanner: checks taskAffinity, launchMode and
allowTaskReparenting of every activity and reports the ones a malicious app can
pull into its own task by declaring the same affinity.

Android 11 (API 30) stopped matching tasks of other UIDs by affinity, so with
minSdk >= 30 everything is reported as informational.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apkscan.apk import api_label
from apkscan.report import (HIGH, INFO, MEDIUM, OK, Finding, base_parser, emit_json, exit_code, load_apk,
                            print_findings, print_header, summary_line)

TASK_HIJACK_FIXED_API = 30


def effective_affinity(m, act):
    """(affinity, where it comes from); '' means no affinity"""
    if act.task_affinity is not None:
        return act.task_affinity, "activity attribute"
    if m.app_task_affinity is not None:
        return m.app_task_affinity, "<application android:taskAffinity>"
    return m.package, "default (package name)"


def build_findings(apk, show_all):
    m = apk.manifest
    min_sdk = m.min_sdk or 1
    fixed_everywhere = min_sdk >= TASK_HIJACK_FIXED_API

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
                findings.append(Finding(INFO, act.name, "Activity disabled in manifest; skipped."))
            continue
        aliases = [a for a in aliases_of.get(act.name, []) if a.is_enabled()]
        exported = act.is_exported() or any(a.is_exported() for a in aliases)
        launcher = act.is_launcher() or any(a.is_launcher() for a in aliases)
        launch_mode = act.launch_mode or "standard"
        affinity, affinity_src = effective_affinity(m, act)
        if act.allow_task_reparenting is not None:
            reparent = act.allow_task_reparenting
        else:
            reparent = bool(m.app_allow_task_reparenting)

        details = {
            "launchMode": launch_mode,
            "taskAffinity": '"%s"' % affinity,
            "allowTaskReparenting": "true" if reparent else "false",
            "exported": "%s (%s)" % ("yes" if exported else "no", act.exported_reason()),
        }
        if launcher:
            details["launcher"] = "yes (MAIN/LAUNCHER)"
        if aliases:
            details["aliases"] = [a.name for a in aliases]
        if act.permission:
            details["permission"] = act.permission

        if launch_mode == "singleInstance":
            findings.append(Finding(OK, act.name, "launchMode=singleInstance: always alone in its own task, affinity is not "
                                    "used to place it, so it cannot end up in a foreign task.", details=details))
            continue
        if affinity == "":
            findings.append(Finding(OK, act.name, 'taskAffinity="": no affinity, an attacker task cannot claim it.', details=details))
            continue

        reasons, fixes = [], []
        if launcher:
            severity = HIGH
            title = ('Launcher activity with a claimable task affinity: a malicious app declaring taskAffinity="%s" gets its '
                     "task brought to the front (or reparented on top) when the user opens this app from the home screen "
                     "(classic StrandHogg)." % affinity)
            reasons.append("the launcher start always uses FLAG_ACTIVITY_NEW_TASK, so the system looks for an existing task "
                           "with matching affinity and reuses the attacker's")
        elif launch_mode in ("singleTask", "singleInstancePerTask"):
            severity = HIGH
            title = ("launchMode=%s with a claimable task affinity: the activity is always routed into the task whose affinity "
                     "matches, i.e. the attacker's, where a phishing activity can sit on top of it." % launch_mode)
            reasons.append("singleTask resolves its host task purely by affinity before creating one")
        elif reparent:
            severity = HIGH
            title = ("allowTaskReparenting=true with a claimable task affinity: when the attacker's task (same affinity) comes "
                     "to the foreground this activity moves into it and the attacker controls what the user sees next.")
        elif exported:
            severity = MEDIUM
            title = ("Exported activity with a claimable task affinity: a malicious app can start it with FLAG_ACTIVITY_NEW_TASK "
                     "so it lands in the attacker's task (same affinity), then push its own activity on top of the real screen.")
        else:
            if not show_all:
                continue
            severity = INFO
            title = ("Non-exported activity with a claimable task affinity: other apps cannot start it, but it will live inside "
                     "a hijacked task if the app's own task was already claimed (see launcher / singleTask findings).")

        if affinity_src != "activity attribute":
            reasons.append("affinity comes from the %s, the activity does not set its own" % affinity_src)
        if affinity != m.package:
            reasons.append('custom affinity "%s" is public (it is in the manifest) and can be copied by any app; only the empty '
                           "string is safe" % affinity)
        if act.permission:
            reasons.append("protected by permission %s: other apps cannot start it directly, task placement of the app's own "
                           "launches is unaffected" % act.permission)
        commands = []
        if exported and severity in (HIGH, MEDIUM):
            commands.append("adb shell am start -n %s/%s -f 0x10000000" % (m.package, act.name))

        if fixed_everywhere:
            severity = INFO
            reasons.append("minSdk %d >= 30: every device this app installs on has the Android 11 fix (tasks of other UIDs are "
                           "no longer matched by affinity). Not exploitable, reported for hygiene only." % min_sdk)
        else:
            reasons.append("exploitable on devices running %s .. API 29 (Android 10); fixed from Android 11" % api_label(min_sdk))
            reasons.append("StrandHogg 2.0 (CVE-2020-0096) also hijacks tasks without affinity tricks on unpatched Android 8-10; "
                           "only security patches help there")
        fixes.append('set android:taskAffinity="" on this activity (or on <application> for all of them) so it never shares a '
                     "task with another app")
        if severity == HIGH and launch_mode in ("singleTask", "singleInstancePerTask"):
            fixes.append("if a dedicated task is really needed use launchMode=singleInstance instead of singleTask")
        if reparent:
            fixes.append('remove android:allowTaskReparenting="true"')
        if not fixed_everywhere:
            fixes.append("raising minSdkVersion to 30 removes the attack surface entirely")
        findings.append(Finding(severity, act.name, title, reasons, fixes, details, commands))
    return findings


def main(argv=None):
    args = base_parser(__doc__).parse_args(argv)
    apk = load_apk(args)
    findings = build_findings(apk, args.all)
    m = apk.manifest
    fixed = (m.min_sdk or 1) >= TASK_HIJACK_FIXED_API
    if args.json:
        emit_json(apk, "task-hijacking", findings, {"fixed_on_all_devices": fixed})
        return exit_code(findings)
    print_header(apk, "Task hijacking scanner", [
        "Android 11 task-affinity fix on all supported devices: "
        + ("yes (minSdk >= 30, findings informational)" if fixed
           else "no (devices on %s .. API 29 are exploitable)" % api_label(m.min_sdk)),
        "<application android:taskAffinity>: %s" % (repr(m.app_task_affinity) if m.app_task_affinity is not None
                                                     else "not set (default = package name)"),
    ])
    print_findings(findings, args.all)
    print(summary_line(findings))
    return exit_code(findings)


if __name__ == "__main__":
    sys.exit(main())
