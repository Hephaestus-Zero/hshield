# hshield — Linux Kernel Containment & Supply-Chain Security Engine

[![CI](https://github.com/Hephaestus-Zero/hshield/actions/workflows/ci.yml/badge.svg)](https://github.com/Hephaestus-Zero/hshield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

`hshield` is a zero-dependency C11 defensive security toolkit for Linux workstations and developer environments running untrusted repositories, build scripts, and machine-learning artifacts. It combines unprivileged Linux Security Module (**Landlock LSM**) process sandboxing, privileged runtime telemetry/containment (`fanotify` + `CN_PROC` + `AES-256-GCM` quarantine), AI coding-agent repository trap auditing, and zero-execution **Pickle VM / ZIP** static supply-chain scanning.

## Threat Model & Defensive Scope

Modern software and ML workflows routinely ingest third-party repositories and serialized checkpoints where static assumptions fail:

1. **Credential & Browser Session Harvesting During Build/Test:** Untrusted `setup.py`, `Makefile`, or test hooks reading `~/.ssh`, `~/.gnupg`, encrypted vaults, or browser cookie stores, or modifying shell startup files (`~/.bashrc`, `~/.profile`).
2. **Coding-Agent Repository Traps & Trojan-Source Unicode:** Cloned repositories planting workspace `.mcp.json` servers, `.claude/settings.json` hooks, or invisible Bidirectional/Zero-Width Unicode (`U+202A..U+202E`, `U+200B..U+200D`) inside `AGENTS.md` / `CLAUDE.md`.
3. **Serialized ML Checkpoint Deserialization (`Pickle` RCE):** Malicious `.pkl`, `.pt`, `.pth`, and `.ckpt` archives invoking `GLOBAL` / `STACK_GLOBAL` + `REDUCE` chains (`posix.system`, `subprocess.Popen`, `builtins.eval`) upon model load.
4. **Runtime In-Memory Stagers:** Fileless `memfd_create` + `fexecve` execution and anonymous `RW -> RWX` shellcode transitions distinguished from legitimate `libffi`, `pcre2`, and `V8` JIT arenas.

`hshield` is strictly a **defensive containment, triage, and static/runtime verification** tool.

## Components

| Binary | Privilege | Core Primitives | Purpose |
|---|---|---|---|
| `hshield sandbox` | Unprivileged (`PR_SET_NO_NEW_PRIVS`) | Linux Landlock LSM (`ABI v1–v6`, `LANDLOCK_SCOPE_SIGNAL`, `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`) | Launches arbitrary commands with read-only OS mounts, hidden `$HOME` credential directories, and optional `--allow-write <dir>` scoping. |
| `hshield audit` | Unprivileged | Deterministic file & UTF-8 codepoint scanner | Audits untrusted directories for `.mcp.json` / `.claude` / `.codex` hook traps, Trojan-Source bidirectional UTF-8 sequences, and `/etc/ld.so.preload` tampering. |
| `hshield --daemon` | `CAP_SYS_ADMIN` (optional) | `fanotify` (`FAN_OPEN_PERM`), `NETLINK_CONNECTOR` (`CN_PROC`), `timerfd`, OpenSSL `EVP_aes_256_gcm` | Zero-idle-polling runtime exec inspection, canary trap enforcement, and AES-256-GCM forensic binary quarantine. |
| `hshield-supply-scan` | Unprivileged | In-RAM `zlib` ZIP Central Directory parser + Pickle Protocol 0–5 opcode analyzer | Statically inspects `.pkl`, `.pt`, `.pth`, `.ckpt`, `.zip`, and downloaded scripts without importing Python or executing bytecode. |

## Build & Verification

Requires `gcc` (C11), Linux kernel headers (`>= 5.13` for Landlock LSM, `>= 6.12` for ABI v6 IPC scoping), `libcrypto` (OpenSSL), `zlib`, and `python3` (for the automated test suite).

```bash
make
make test
```

## CLI Usage

```bash
# Run an untrusted test suite or script inside Landlock LSM containment
./hshield sandbox --allow-write /tmp/build-out -- pytest -q

# Audit a cloned repository before opening it in an IDE or coding agent
./hshield audit /path/to/cloned-repo --json

# Statically scan ML checkpoints or archives before loading weights
./hshield-supply-scan --json model_weights.pt archive.zip
```

## License

MIT License — Copyright (c) 2026 Hephaestus-Zero.
