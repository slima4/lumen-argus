"""Attribution guards — keep NOTICE.md honest as we add/remove upstream content."""

import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
NOTICE = REPO_ROOT / "NOTICE.md"
LICENSES_DIR = REPO_ROOT / "third_party" / "LICENSES"


class TestNoticeFilePresent(unittest.TestCase):
    def test_notice_exists(self):
        self.assertTrue(NOTICE.is_file(), f"missing repo-root NOTICE.md at {NOTICE}")

    def test_licenses_dir_exists(self):
        self.assertTrue(LICENSES_DIR.is_dir(), f"missing {LICENSES_DIR}")

    def test_notice_mentions_every_adapted_upstream(self):
        text = NOTICE.read_text()
        # Upstream projects we pull rule content or code from.
        for upstream in ("gitleaks", "phonenumbers", "aiohttp", "pyahocorasick", "pyyaml"):
            self.assertIn(upstream, text.lower(), f"NOTICE.md does not mention {upstream}")

    def test_notice_references_every_license_file(self):
        text = NOTICE.read_text()
        for path in LICENSES_DIR.glob("*.txt"):
            self.assertIn(
                path.name,
                text,
                f"NOTICE.md does not reference {path.name} — attribution drift",
            )

    def test_license_files_nonempty(self):
        for path in LICENSES_DIR.glob("*.txt"):
            self.assertGreater(path.stat().st_size, 100, f"{path} is suspiciously small")

    def test_gitleaks_tagged_rules_listed_in_notice(self):
        import json

        community = json.loads(
            (REPO_ROOT / "packages" / "proxy" / "lumen_argus" / "rules" / "community.json").read_text()
        )
        gitleaks_rules = sorted(r["name"] for r in community["rules"] if "gitleaks" in r.get("tags", []))
        self.assertTrue(gitleaks_rules, "no gitleaks-tagged rules found — sanity check failed")

        notice_text = NOTICE.read_text()
        # Every gitleaks-tagged rule must be named in NOTICE.md so provenance
        # can't silently drift if a rule is added/removed.
        for name in gitleaks_rules:
            self.assertIn(
                name,
                notice_text,
                f"rule {name!r} is tagged gitleaks but not listed in NOTICE.md",
            )


class TestProxyPackageAttribution(unittest.TestCase):
    """Attribution files must ship INSIDE the proxy wheel (next to community.json)
    so Gitleaks' MIT clause is honored for pip-installed users, not only for
    repo readers. These guards fail if the files are missing or if the
    pyproject package-data config stops including them."""

    RULES_DIR = REPO_ROOT / "packages" / "proxy" / "lumen_argus" / "rules"
    PYPROJECT = REPO_ROOT / "packages" / "proxy" / "pyproject.toml"

    def test_package_notice_exists(self):
        self.assertTrue((self.RULES_DIR / "NOTICE").is_file())

    def test_package_gitleaks_license_exists(self):
        path = self.RULES_DIR / "LICENSE-gitleaks.txt"
        self.assertTrue(path.is_file())
        self.assertIn("MIT License", path.read_text())

    def test_pyproject_ships_attribution(self):
        # Parse the pyproject so we assert against the *actual* package-data
        # config, not a substring that could live in a comment or unrelated
        # string and give a false pass.
        import tomllib

        cfg = tomllib.loads(self.PYPROJECT.read_text())
        rules_data = cfg["tool"]["setuptools"]["package-data"]["lumen_argus.rules"]
        self.assertIn("NOTICE", rules_data, "package-data missing NOTICE entry")
        self.assertIn("LICENSE-*.txt", rules_data, "package-data missing LICENSE-*.txt entry")

    def test_package_notice_names_same_gitleaks_rules_as_root(self):
        import json

        community = json.loads((self.RULES_DIR / "community.json").read_text())
        gitleaks_rules = {r["name"] for r in community["rules"] if "gitleaks" in r.get("tags", [])}
        pkg_notice = (self.RULES_DIR / "NOTICE").read_text()
        for name in gitleaks_rules:
            self.assertIn(
                name,
                pkg_notice,
                f"rule {name!r} tagged gitleaks but missing from proxy package NOTICE",
            )


if __name__ == "__main__":
    unittest.main()
