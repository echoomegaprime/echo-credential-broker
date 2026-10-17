import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location("operator_journey", Path(__file__).with_name("certforge_operator_journey.py"))
journey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journey)


class JourneyTests(unittest.TestCase):
    def test_node_version_boundary(self):
        self.assertFalse(journey.node_supported("v22.11.0"))
        self.assertFalse(journey.node_supported("unknown"))
        self.assertTrue(journey.node_supported("v22.12.0\n"))
        self.assertTrue(journey.node_supported("v24.0.0"))

    def test_missing_node_fails_honestly(self):
        out = io.StringIO()
        with patch.object(journey.shutil, "which", return_value=None), contextlib.redirect_stdout(out):
            self.assertEqual(journey.main(), 1)
        self.assertIn("node_runtime_missing", out.getvalue())
        self.assertNotIn("JOURNEY_OK", out.getvalue())

    def test_no_install_migrate_production_or_network_commands(self):
        self.assertEqual(len(journey.COMMANDS), 2)
        for argv in journey.COMMANDS:
            self.assertIn("--test", argv)
            self.assertNotIn("npm", argv)
            self.assertNotIn("scripts/sdk-operator.ts", argv)

    def test_dependency_failure_is_not_certification(self):
        out = io.StringIO()
        with patch.object(journey.shutil, "which", return_value="node"), \
             patch.object(journey, "run", return_value="v24.0.0"), \
             patch.object(journey, "source_contract", side_effect=OSError("private-source-path")), \
             contextlib.redirect_stdout(out):
            self.assertEqual(journey.main(), 1)
        self.assertNotIn("private-source-path", out.getvalue())
        self.assertIn("NOT_READY", out.getvalue())

    def test_subprocess_nonzero_is_failure(self):
        with patch.object(journey.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "private-detail")):
            with self.assertRaises(journey.NotReady) as caught:
                journey.run(["node"], 1, env={})
        self.assertEqual(str(caught.exception), "offline_command_failed")

    def test_timeout_is_fixed_failure(self):
        out = io.StringIO()
        with patch.object(journey.shutil, "which", return_value="node"), \
             patch.object(journey.subprocess, "run", side_effect=subprocess.TimeoutExpired("private-command", 1)), \
             contextlib.redirect_stdout(out):
            self.assertEqual(journey.main(), 1)
        self.assertNotIn("private-command", out.getvalue())

    def test_missing_tap_is_not_success(self):
        for output in ("", "all good", "# tests 44\n# pass 44\n", "# tests 44\n# pass 43\n# fail 0\n",
                       "# tests 43\n# pass 43\n# fail 0\n", "# tests 44\n# pass 44\n# fail 1\n"):
            with self.subTest(output=output), self.assertRaises(journey.NotReady):
                journey.tap_passed(output, 44)

    def test_complete_tap(self):
        self.assertEqual(journey.tap_passed("# tests 44\n# pass 44\n# fail 0\n", 44), 44)

    def test_contract_drift_fails(self):
        values = ["v24.0.0", "", "# tests 44\n# pass 44\n# fail 0\n", "# tests 1\n# pass 1\n# fail 0\n"]
        out = io.StringIO()
        with patch.object(journey.shutil, "which", return_value="node"), \
             patch.object(journey, "run", side_effect=values), \
             patch.object(journey, "source_contract", side_effect=["first", "changed"]), \
             contextlib.redirect_stdout(out):
            self.assertEqual(journey.main(), 1)
        self.assertIn("contract_changed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
