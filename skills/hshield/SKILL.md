---
name: hshield
description: Zero-overhead Linux Landlock LSM filesystem and TCP network sandbox plus AST supply-chain auditor for AI coding agents. Use before running untrusted scripts, third-party repositories, build hooks, or autonomous agent commands.
---

# `hshield` — Zero-Overhead Kernel Containment & Supply-Chain Auditor

Protect local secrets (`~/.ssh`, `~/.aws`, browser profiles, dotfiles) and catch repository traps before running untrusted code or AI coding tools on Linux (`Landlock ABI v1–v6`).

## Core Commands

1. **Coding-agent sandbox preset (`RW` current directory + read-only OS + only HTTPS `TCP 443`, hides `$HOME` secrets)**:
   ```bash
   hshield agent -- claude
   hshield sandbox --agent --allow-write ./workspace -- pytest -q
   ```
2. **Offline / custom TCP port Landlock confinement (`ABI v4+`)**:
   ```bash
   hshield sandbox --deny-net --allow-write /tmp/out -- python3 setup.py
   hshield sandbox --deny-net --allow-tcp-connect 443,8443 -- npm test
   hshield sandbox --deny-net --allow-tcp-bind 8080 -- python3 -m http.server 8080
   ```
3. **Pre-open repository supply-chain & prompt-trap audit**:
   ```bash
   hshield audit /path/to/cloned-repo --json
   ```
4. **Zero-import Pickle VM (Protocols 0–5) & PyTorch ZIP RCE scanner**:
   ```bash
   hshield-supply-scan --json model.pt dataset.pkl archive.zip
   ```

## Installation

- **Homebrew (Linuxbrew):** `brew install Hephaestus-Zero/tap/hshield`
- **Quick Binary / Source Script (`x86_64`):** `curl -fsSL https://raw.githubusercontent.com/Hephaestus-Zero/hshield/main/install.sh | sh`
- **Build from Source:** `make && make test && sudo make install`
