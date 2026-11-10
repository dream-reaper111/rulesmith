import tempfile
import unittest
from pathlib import Path

from rulesmith.core import RuleError, lint_sigma, lint_suricata, lint_yara, scan_directory

SIGMA = b"""title: Isolated test rule
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
detection:
  selection:
    Image: test-only.exe
  condition: selection
level: low
tags:
  - attack.t1059
falsepositives:
  - Test fixture only
"""


class CoreTests(unittest.TestCase):
    def test_sigma_structure_and_declared_tag(self):
        result = lint_sigma(SIGMA)
        self.assertEqual(result["status"], "precheck_only")
        self.assertEqual(result["declared_attack_tags"], ["attack.t1059"])
        self.assertEqual(result["errors"], [])

    def test_sigma_duplicate_key_and_alias_rejected(self):
        duplicate = b"title: One\ntitle: Two\nlogsource: {category: test}\ndetection: {selection: {a: b}, condition: selection}\n"
        alias = b"title: &x One\nlogsource: {category: *x}\n"
        self.assertEqual(lint_sigma(duplicate)["status"], "invalid")
        self.assertEqual(lint_sigma(alias)["status"], "invalid")

    def test_unknown_selector_and_complex_condition_warning(self):
        unknown = SIGMA.replace(b"condition: selection", b"condition: missing")
        self.assertIn("undefined", " ".join(lint_sigma(unknown)["errors"]))
        complex_rule = SIGMA.replace(b"condition: selection", b"condition: selection and not filter")
        self.assertIn("condition semantics require pySigma validation", lint_sigma(complex_rule)["warnings"])

    def test_yara_and_suricata_are_prechecks(self):
        yara = lint_yara(b"rule Test { condition: true }")
        self.assertEqual(yara["status"], "precheck_only")
        self.assertEqual(yara["engine_validation"], "not run")
        suricata = lint_suricata(b'alert tcp any any -> any any (msg:"test"; sid:123; rev:1;)')
        self.assertEqual(suricata["status"], "precheck_only")
        self.assertEqual(suricata["errors"], [])

    def test_scan_detects_duplicates_and_skips_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.yml").write_bytes(SIGMA)
            (root / "b.yml").write_bytes(SIGMA)
            (root / "outside.yml").symlink_to(root / "a.yml")
            result = scan_directory(root)
            self.assertEqual(result["file_count"], 2)
            self.assertIn("duplicate content", " ".join(result["files"][1]["warnings"]))

    def test_rule_size_bound(self):
        with self.assertRaises(RuleError):
            lint_sigma(b"x" * 262145)


if __name__ == "__main__":
    unittest.main()
