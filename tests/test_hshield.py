import json
import os
from pathlib import Path
import pickle
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


if __name__ == "__main__":
    unittest.main()
