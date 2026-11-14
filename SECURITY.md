# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` (`main`) | Yes |

## Reporting a Vulnerability

Please report sandbox escapes, Landlock ruleset bypasses, `fanotify`/`CN_PROC` race conditions, or Pickle/ZIP parser evasion issues privately via [GitHub Private Vulnerability Reporting](https://github.com/Hephaestus-Zero/hshield/security/advisories/new) before public disclosure.

Include kernel version (`uname -r`), Landlock ABI version, minimal reproduction steps, and expected vs. observed containment behavior. Initial triage target is 72 hours.
