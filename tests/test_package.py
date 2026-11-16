"""Repository-level checks: packaging, documentation and CI configuration."""

import ast
import contextlib
import io
import re
import unittest
from pathlib import Path

import syslogrouter
from syslogrouter.cli import main
from syslogrouter.parser import parse_line

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "syslogrouter"
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
LICENSE = ROOT / "LICENSE"
GITIGNORE = ROOT / ".gitignore"
EXAMPLES = ROOT / "examples"

# Banned tokens are assembled from pieces so that these checks do not match
# their own source file, which would make a repository-wide scan noisy.
PLACEHOLDER_MARKERS = ("to" + "do", "tb" + "d", "coming " + "soon", "fix" + "me", "place" + "holder")
SOURCE_MARKERS = ("TO" + "DO", "FIX" + "ME", "X" * 3)
MACHINE_PATH_PREFIXES = ("C:" + "\\", "Us" + "ers\\", "/ho" + "me/")
AI_WORDS = ("A" + "I", "LL" + "M", "G" + "PT", "Chat" + "GPT", "Copi" + "lot", "Cla" + "ude")
PRIVATE_KEY_PREFIX = "-" * 5 + "BEGIN"

REQUIRED_MODULES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "engine.py",
    "parser.py",
    "report.py",
    "rules.py",
    "store.py",
)

REQUIRED_HEADINGS = (
    "# syslog-router",
    "## Features",
    "## Quick start",
    "## Usage",
    "## Architecture",
    "## Project layout",
    "## Testing",
    "## Roadmap",
    "## Resumo em português (PT-PT)",
    "## License",
)


def read(path):
    return path.read_text(encoding="utf-8")


class PackageTests(unittest.TestCase):
    """The importable package and its entry points."""

    def test_version(self):
        self.assertRegex(syslogrouter.__version__, r"^\d+\.\d+\.\d+$")

    def test_required_modules_exist(self):
        for name in REQUIRED_MODULES:
            with self.subTest(module=name):
                self.assertTrue((SRC / name).is_file())

    def test_every_module_has_a_docstring(self):
        for name in REQUIRED_MODULES:
            with self.subTest(module=name):
                tree = ast.parse(read(SRC / name))
                self.assertIsNotNone(ast.get_docstring(tree), f"{name} has no docstring")

    def test_public_api_imports(self):
        from syslogrouter import cli, engine, parser, report, rules, store

        self.assertTrue(callable(cli.main))
        self.assertTrue(callable(parser.parse_line))
        self.assertTrue(callable(engine.run))
        self.assertTrue(callable(rules.load_rules))
        self.assertTrue(callable(store.Store))
        self.assertTrue(callable(report.build_dashboard))

    def test_cli_main_returns_int(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["version"]), 0)

    def test_no_third_party_imports(self):
        allowed = {
            "__future__",
            "argparse",
            "contextlib",
            "dataclasses",
            "datetime",
            "fnmatch",
            "html",
            "json",
            "pathlib",
            "re",
            "sqlite3",
            "sys",
            "typing",
        }
        for name in REQUIRED_MODULES:
            tree = ast.parse(read(SRC / name))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split(".")[0], allowed)
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    self.assertIn(node.module.split(".")[0], allowed)


class PyprojectTests(unittest.TestCase):
    """pyproject.toml metadata (parsed as text for Python 3.10 compatibility)."""

    def setUp(self):
        self.content = read(PYPROJECT)

    def test_name_and_version(self):
        self.assertIn('name = "syslogrouter"', self.content)
        self.assertIn('version = "1.0.0"', self.content)

    def test_no_runtime_dependencies(self):
        self.assertIn("dependencies = []", self.content)

    def test_requires_python(self):
        self.assertIn('requires-python = ">=3.10"', self.content)

    def test_console_script(self):
        self.assertIn('syslogrouter = "syslogrouter.cli:main"', self.content)

    def test_readme_and_license(self):
        self.assertIn('readme = "README.md"', self.content)
        self.assertIn('license = { text = "MIT" }', self.content)

    def test_setuptools_src_layout(self):
        self.assertIn('where = ["src"]', self.content)

    def test_pytest_testpaths(self):
        self.assertIn('testpaths = ["tests"]', self.content)

    def test_no_placeholders(self):
        for placeholder in ("<NAME>", "<DESCRIPTION>", "<KEYWORDS>", "<CONSOLE>", "<PKG>"):
            with self.subTest(placeholder=placeholder):
                self.assertNotIn(placeholder, self.content)


class ReadmeTests(unittest.TestCase):
    """README structure required by the project conventions."""

    def setUp(self):
        self.content = read(README)
        self.lines = self.content.splitlines()

    def test_exists(self):
        self.assertTrue(README.is_file())

    def test_required_headings(self):
        for heading in REQUIRED_HEADINGS:
            with self.subTest(heading=heading):
                self.assertIn(heading, self.content)

    def test_badges(self):
        self.assertIn(
            "https://github.com/jeremydacosta-TechOptimist/syslog-router/actions/workflows/ci.yml/badge.svg",
            self.content,
        )
        self.assertIn("https://img.shields.io/badge/python-3.10%2B-blue", self.content)
        self.assertIn("https://img.shields.io/badge/license-MIT-green", self.content)

    def test_architecture_diagram(self):
        self.assertIn("```mermaid", self.content)

    def test_project_layout_tree(self):
        self.assertIn("src/syslogrouter/", self.content)
        self.assertIn("examples/lab-logs/mixed.log", self.content)

    def test_testing_commands(self):
        self.assertIn("py -3.13 -m pytest -q", self.content)
        self.assertIn("python -m unittest discover -s tests", self.content)
        self.assertIn("python -m compileall -q src tests", self.content)

    def test_pt_pt_summary_bullets(self):
        section = self.content.split("## Resumo em português (PT-PT)", 1)[1]
        section = section.split("## License", 1)[0]
        bullets = [line for line in section.splitlines() if line.startswith("- ")]
        self.assertGreaterEqual(len(bullets), 3)
        self.assertLessEqual(len(bullets), 5)

    def test_quick_start_installs_package(self):
        self.assertIn("pip install -e .", self.content)

    def test_mentions_real_exit_codes(self):
        self.assertIn("Exit codes", self.content)

    def test_no_todo_markers(self):
        lowered = self.content.lower()
        for marker in PLACEHOLDER_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, lowered)

    def test_no_machine_paths(self):
        for prefix in MACHINE_PATH_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertNotIn(prefix, self.content)

    def test_no_ai_mentions(self):
        for word in AI_WORDS:
            with self.subTest(word=word):
                self.assertIsNone(
                    re.search(rf"\b{word}\b", self.content),
                    f"README mentions {word}",
                )

    def test_length_is_reasonable(self):
        self.assertLess(len(self.lines), 260)
        self.assertGreater(len(self.lines), 60)

    def test_license_section(self):
        self.assertIn("MIT © 2026 Jeremy da Costa", self.content)


class RepositoryFilesTests(unittest.TestCase):
    """Static repository configuration files."""

    def test_license_is_mit(self):
        content = read(LICENSE)
        self.assertTrue(content.startswith("MIT License"))
        self.assertIn("2026 Jeremy da Costa", content)

    def test_gitignore_entries(self):
        content = read(GITIGNORE)
        for entry in ("__pycache__/", ".venv/", "out/", "*.py[cod]"):
            with self.subTest(entry=entry):
                self.assertIn(entry, content)

    def test_ci_matrix(self):
        content = read(CI)
        for version in ('"3.10"', '"3.11"', '"3.12"', '"3.13"'):
            with self.subTest(version=version):
                self.assertIn(version, content)

    def test_ci_runs_tests_and_help(self):
        content = read(CI)
        self.assertIn("python -m pytest -q", content)
        self.assertIn("python -m syslogrouter --help", content)

    def test_ci_placeholder_replaced(self):
        self.assertNotIn("<PKG>", read(CI))

    def test_no_committed_databases_or_reports(self):
        for path in EXAMPLES.rglob("*"):
            if path.is_file():
                with self.subTest(path=path.name):
                    self.assertNotIn(path.suffix, {".db", ".sqlite", ".sqlite3", ".html"})

    def test_example_files_are_small(self):
        for path in EXAMPLES.rglob("*"):
            if path.is_file():
                with self.subTest(path=path.name):
                    self.assertLess(path.stat().st_size, 200 * 1024)

    def test_no_private_key_material(self):
        candidates = [README, PYPROJECT, LICENSE, GITIGNORE, CI]
        candidates.extend(SRC.glob("*.py"))
        candidates.extend(
            path for path in (ROOT / "tests").glob("*.py") if path.name != "test_package.py"
        )
        candidates.extend(
            path
            for path in EXAMPLES.rglob("*")
            if path.is_file() and path.suffix in {".log", ".json", ".md", ".txt"}
        )
        for path in candidates:
            content = path.read_text(encoding="utf-8", errors="ignore")
            with self.subTest(path=path.name):
                self.assertNotIn(PRIVATE_KEY_PREFIX, content)

    def test_source_has_no_todo_comments(self):
        candidate_sources = list(SRC.glob("*.py"))
        candidate_sources.extend(
            path for path in (ROOT / "tests").glob("*.py") if path.name != "test_package.py"
        )
        for path in candidate_sources:
            content = read(path)
            for marker in SOURCE_MARKERS:
                with self.subTest(path=path.name, marker=marker):
                    self.assertNotIn(marker, content)

    def test_parser_module_has_no_side_effects_on_import(self):
        message = parse_line("<13>1 - host app - - - hello")
        self.assertEqual(message.msg, "hello")


if __name__ == "__main__":
    unittest.main()
