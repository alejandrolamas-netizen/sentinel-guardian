import json
import unittest
from sentinel_prompt import analyze_code

class SentinelAnalysisTests(unittest.TestCase):
    def report(self, source):
        return json.loads(analyze_code(source))
    def test_dynamic_execution(self):
        r = self.report("result = eval(user_input)\n")
        self.assertEqual(r["findings"][0]["rule_id"], "PY001")
    def test_shell_true(self):
        r = self.report("import subprocess\nsubprocess.run(cmd, shell=True)\n")
        self.assertIn("PY002", [x["rule_id"] for x in r["findings"]])
    def test_pickle(self):
        r = self.report("import pickle\npickle.loads(payload)\n")
        self.assertIn("PY003", [x["rule_id"] for x in r["findings"]])
    def test_unsafe_yaml(self):
        r = self.report("import yaml\nyaml.load(payload)\n")
        self.assertIn("PY004", [x["rule_id"] for x in r["findings"]])
    def test_safe_yaml_loader(self):
        r = self.report("import yaml\nyaml.load(payload, Loader=yaml.SafeLoader)\n")
        self.assertNotIn("PY004", [x["rule_id"] for x in r["findings"]])
    def test_possible_hardcoded_secret(self):
        r = self.report('API_KEY = "not-a-real-example-value"\n')
        self.assertIn("PY005", [x["rule_id"] for x in r["findings"]])
    def test_placeholder_not_reported(self):
        self.assertEqual(self.report('API_KEY = "your_api_key"\n')["status"], "no_findings")
    def test_syntax_error(self):
        self.assertEqual(self.report("def broken(:\n")["status"], "parse_error")

if __name__ == "__main__":
    unittest.main()
