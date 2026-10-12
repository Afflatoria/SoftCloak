import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RuffTests(unittest.TestCase):
    def test_ruff_lint(self):
        self._run_ruff("check")

    def test_ruff_format(self):
        self._run_ruff("format", "--check")

    def _run_ruff(self, *args: str) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "ruff", *args, "src", "tests"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return
        detail = (result.stdout + result.stderr).strip()
        if "No module named ruff" in detail:
            self.fail(
                'ruff is not installed. Install the dev extra: pip install -e ".[dev]"'
            )
        self.fail(detail)
