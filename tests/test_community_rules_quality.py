"""Quality gates on packages/proxy/lumen_argus/rules/community.json.

Runs Crossfire (https://github.com/lumen-argus/crossfire) to assert that
the shipped rule set is syntactically valid and free of internal duplicates.
Skipped when Crossfire is not installed (e.g. local dev without the
rules-analysis extra).
"""

import pathlib
import shutil
import subprocess
import unittest

COMMUNITY_JSON = (
    pathlib.Path(__file__).resolve().parents[1] / "packages" / "proxy" / "lumen_argus" / "rules" / "community.json"
)


@unittest.skipUnless(shutil.which("crossfire"), "crossfire CLI not on PATH")
class TestCommunityRulesQuality(unittest.TestCase):
    def test_community_json_exists(self):
        self.assertTrue(COMMUNITY_JSON.is_file(), f"missing: {COMMUNITY_JSON}")

    def test_no_invalid_regex(self):
        r = subprocess.run(
            ["crossfire", "validate", str(COMMUNITY_JSON)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, f"crossfire validate failed:\n{r.stdout}\n{r.stderr}")

    def test_no_internal_duplicates(self):
        r = subprocess.run(
            [
                "crossfire",
                "scan",
                str(COMMUNITY_JSON),
                "--fail-on-duplicate",
                "--format",
                "summary",
                "--skip-invalid",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(r.returncode, 0, f"crossfire scan found duplicates:\n{r.stdout}\n{r.stderr}")


if __name__ == "__main__":
    unittest.main()
