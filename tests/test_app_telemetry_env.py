"""Every Festival App process that verification starts runs with usage reporting off."""
import ast
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from app_environment import without_app_telemetry

LAUNCHERS = ("verify_app_candidate.py", "verify_app_upgrade.py", "linux_guest_app.py")
APP_BINARIES = {"binary", "appimage", "extracted"}


def app_launches(tree):
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Popen"):
            continue
        argv = node.args[0] if node.args else None
        if not isinstance(argv, ast.List) or not argv.elts:
            continue
        first = argv.elts[0]
        if isinstance(first, ast.Call) and first.args:
            first = first.args[0]
        if isinstance(first, ast.Name) and first.id in APP_BINARIES:
            yield node


def env_name(call):
    for keyword in call.keywords:
        if keyword.arg == "env":
            value = keyword.value
            if isinstance(value, ast.Name):
                return value.id
            if isinstance(value, ast.Attribute):
                return value.attr
    return None


def guarded_names(tree):
    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "without_app_telemetry":
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
                elif isinstance(target, ast.Attribute):
                    names.add(target.attr)
    return names


class AppTelemetryEnvironmentTests(unittest.TestCase):
    def test_helper_turns_reporting_off_and_keeps_other_keys(self):
        self.assertEqual(without_app_telemetry({"HOME": "/h", "FESTIVAL_APP_TELEMETRY": "1"}),
                         {"HOME": "/h", "FESTIVAL_APP_TELEMETRY": "0"})

    def test_helper_does_not_mutate_its_input(self):
        source = {"PATH": "/bin"}
        without_app_telemetry(source)
        self.assertEqual(source, {"PATH": "/bin"})

    def test_every_app_launch_uses_a_guarded_environment(self):
        launches = 0
        for name in LAUNCHERS:
            tree = ast.parse((SCRIPTS / name).read_text(), filename=name)
            guarded = guarded_names(tree)
            for call in app_launches(tree):
                launches += 1
                env = env_name(call)
                with self.subTest(script=name, line=call.lineno):
                    self.assertIsNotNone(env, f"{name}:{call.lineno} starts the App without an explicit env")
                    self.assertTrue(env in guarded or env == "app_environment",
                                    f"{name}:{call.lineno} starts the App with env={env}, not from without_app_telemetry")
        self.assertGreaterEqual(launches, 10, "expected to find every App launch site")

    def test_app_environment_alias_is_guarded(self):
        tree = ast.parse((SCRIPTS / "verify_app_candidate.py").read_text())
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "app_environment" for t in n.targets)]
        self.assertTrue(assigns)
        for node in assigns:
            value = node.value
            ok = (isinstance(value, ast.Name) and value.id == "environment") or (
                isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "without_app_telemetry")
            self.assertTrue(ok, f"app_environment assigned at line {node.lineno} bypasses the guard")


if __name__ == "__main__":
    unittest.main()
