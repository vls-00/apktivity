<pre align="center">
   ___      ___   _  __    _        _               _      _       _  _  
  /   \    | _ \ | |/ /   | |_     (_)    __ __    (_)    | |_    | || | 
  | - |    |  _/ | ' <    |  _|    | |    \ V /    | |    |  _|    \_, | 
  |_|_|   _|_|_  |_|\_\   _\__|   _|_|_   _\_/_   _|_|_   _\__|   _|__/  
_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_| """"| 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
</pre>
>[!warning]
>**For educational purposes, developers and authorized testers only.** 
> 
> Use these tools
> on apps you own or have explicit written permission to assess. Scanning or
> attacking apps without authorization may be illegal. You are responsible for
> how you use them.

Three Python scanners that check an Android `.apk` for common activity
vulnerabilities. Only Python 3.8+ needed.

Auditing these issues by hand means reading the manifest, chasing class
hierarchies through the DEX and cross-referencing SDK behaviour for every
activity. These tools automate the process.

| Scanner | Finds |
|---------|-------|
| `tapjacking_scanner.py` | activities that accept touches while an overlay covers them |
| `deeplink_scanner.py` | exported deep links that can be hijacked or abused |
| `task_hijacking_scanner.py` | activities a malicious app can pull into its task (StrandHogg) |

Each finding prints a verdict, the relevant manifest attributes, **Why** it should be checked and a **Fix** section for remediation. 

>[!note]
>Severity accounts for the APK's minSdk/targetSdk.

Every scanner accepts `--all` (also shows components that look safe) and `--json`
(output).

## Tapjacking

Checks for touch-filtering (`setFilterTouchesWhenObscured`,
`onFilterTouchEventForSecurity`, the `filterTouchesWhenObscured` layout
attribute) and `Window.setHideOverlayWindows` (API 31+). Unprotected exported
activities are HIGH, internal ones MEDIUM.

Android 12's `BLOCK_UNTRUSTED_TOUCHES` is noted but never lowers a rating: it
only blocks overlays above 80% opacity, so an 80%-opacity or cut-out overlay
still works. Also flags launchers, cross-platform UI frameworks (Flutter, React
Native, Capacitor, etc.), no-UI trampolines, and sensitive-looking names.

- `--deep`: scan the whole DEX for custom mitigations.

```
python3 tapjacking_scanner.py --all --deep app.apk
```

## Deep links

Expands every exported `<intent-filter>` into the URLs it accepts and rates each:

- **Custom schemes** that can be claimed by any app are MEDIUM, or HIGH for sensitive flows.
- **http/https without `autoVerify`** gives a chooser below Android 12, opens in
  the browser from Android 12 on; rating adjusts to the SDK levels.
- **`autoVerify` App Links** are LOW; checked against the host's `assetlinks.json`.
- **Over-broad filters** (no host, wildcard host, `pathPrefix="/"`, `.*`) and
  missing `DEFAULT`/`BROWSABLE` or permissions change the score.
- **Handler code hints**: URI reads, `WebView.loadUrl`, JS bridges, and
  `Intent.parseUri`/`getParcelableExtra` + `startActivity` (intent redirection).

- `--check-assetlinks`: fetch each App Link host's `assetlinks.json` and compare
  it against the APK's real signing cert (network)
- `--strings`: dump the handler class's string literals (parameter names, paths)

```
python3 deeplink_scanner.py --all --check-assetlinks --strings app.apk
```

## Task hijacking

Finds activities a malicious app can pull into its task via a matching
`taskAffinity` (StrandHogg), ranked by affinity, `launchMode`,
`allowTaskReparenting` and exported state:

| Configuration | Severity |
|---------------|----------|
| launcher / `singleTask` / `allowTaskReparenting` | HIGH |
| exported `standard` / `singleTop` | MEDIUM |
| `taskAffinity=""` or `singleInstance` | OK |

Android 11 (API 30) fixed this, so it only affects API 29 and below. With
minSdk >= 30 every finding drops to INFO.

```
python3 task_hijacking_scanner.py --all app.apk
```

## Notes

- Static analysis with heuristics: findings are leads to verify, not proof.
  Confirm each finding manually on the affected API level.
- Only `classes*.dex` in the given file are scanned. Split APKs, app bundles and
  dynamic feature modules must be scanned separately (the tools warn when a class
  is missing).
- Layout and code checks rely on the activity's own classes being present and
  unobfuscated enough to resolve; heavy obfuscation or reflection can hide a
  mitigation and cause a false positive.
