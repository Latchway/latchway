#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PNPM_SETUP = "pnpm/action-setup@7088e561eb65bb68695d245aa206f005ef30921d"


def load_workflow(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path.name} is not an object")
    return value


class CIWorkflowTests(unittest.TestCase):
    def test_pnpm_exists_before_setup_node_reads_its_cache(self) -> None:
        cached_setup_nodes = 0
        for path in sorted(WORKFLOWS.glob("*.yml")):
            workflow = load_workflow(path)
            for job_name, job in workflow["jobs"].items():
                steps = [step for step in job.get("steps", []) if isinstance(step, dict)]
                for index, step in enumerate(steps):
                    if not str(step.get("uses", "")).startswith("actions/setup-node@"):
                        continue
                    if step.get("with", {}).get("cache") != "pnpm":
                        continue
                    cached_setup_nodes += 1
                    self.assertGreater(index, 0, f"{path.name}:{job_name}")
                    package_manager = steps[index - 1]
                    self.assertEqual(
                        package_manager.get("uses"),
                        PNPM_SETUP,
                        f"{path.name}:{job_name}",
                    )
                    self.assertEqual(
                        package_manager.get("if"),
                        step.get("if"),
                        f"{path.name}:{job_name}",
                    )
                    self.assertEqual(
                        package_manager.get("with"),
                        {"version": "10.15.0", "run_install": False},
                        f"{path.name}:{job_name}",
                    )
        self.assertEqual(cached_setup_nodes, 7)

    def test_workflows_have_one_pinned_pnpm_bootstrap(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            self.assertNotIn(
                "corepack prepare pnpm",
                path.read_text(encoding="utf-8"),
                path.name,
            )

    def test_terraform_locks_cover_the_linux_amd64_ci_runner(self) -> None:
        expected = {
            ROOT / "deploy/cloud-run/terraform/.terraform.lock.hcl": (
                "h1:L3O+5UStRwh0MTseTQ7/IlOruySgkWvZJuLMrCs4/D4=",
                "h1:UlBuNVuCGJ39tTv2c5gz2NRZnQbXfbIWbTzWcth5o74=",
            ),
            ROOT / "deploy/aws/terraform/.terraform.lock.hcl": (
                "h1:lTKd2c1EunGxt2XROLgEeSXA2Jk+WiiG9BTcp+L/0xY=",
                "h1:UlBuNVuCGJ39tTv2c5gz2NRZnQbXfbIWbTzWcth5o74=",
            ),
        }
        for path, hashes in expected.items():
            lock = path.read_text(encoding="utf-8")
            for checksum in hashes:
                self.assertIn(f'"{checksum}"', lock, path)


class MakefileFormattingTests(unittest.TestCase):
    def test_fmt_checks_every_tracked_go_file_and_ignores_untracked_files(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("GOFMT ?= $(shell $(GO) env GOROOT)/bin/gofmt", makefile)
        self.assertIn("git ls-files -z -- '*.go' | xargs -0 $(GOFMT) -l", makefile)
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            nested = repository / "nested"
            nested.mkdir()
            tracked = nested / "tracked.go"
            tracked.write_text(
                'package sample\n\nfunc Value(){println("tracked")}\n',
                encoding="utf-8",
            )
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "add", "nested/tracked.go"],
                cwd=repository,
                check=True,
            )

            malformed = subprocess.run(
                ["make", "-f", str(ROOT / "Makefile"), "fmt"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(malformed.returncode, 0)
            self.assertIn("nested/tracked.go", malformed.stdout)

            subprocess.run(["gofmt", "-w", tracked], check=True)
            (repository / "untracked.go").write_text(
                'package sample\n\nfunc Other(){println("untracked")}\n',
                encoding="utf-8",
            )
            clean = subprocess.run(
                ["make", "-f", str(ROOT / "Makefile"), "fmt"],
                cwd=repository,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)


if __name__ == "__main__":
    unittest.main()
