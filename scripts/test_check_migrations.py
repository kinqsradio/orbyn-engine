#!/usr/bin/env python3
"""Tests for the migration check, each against a throwaway git repository."""

import os
import subprocess
import tempfile
import unittest

import check_migrations

HERE = os.getcwd()
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_migrations.py")
MIGRATION = "migrations/0001_first.sql"
KEYSERVICE = "crates/orbyn-keyservice-server/migrations/0001_log.sql"


def sh(repo: str, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def write(repo: str, path: str, text: str) -> None:
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(text)


class Check(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.repo = self.dir.name
        sh(self.repo, "init", "-q", "-b", "main")
        write(self.repo, MIGRATION, "CREATE TABLE a (id int);\n")
        write(self.repo, KEYSERVICE, "CREATE TABLE log (id int);\n")
        write(self.repo, "src/lib.rs", "fn main() {}\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "base")
        sh(self.repo, "checkout", "-qb", "change")
        os.chdir(self.repo)

    def tearDown(self):
        os.chdir(HERE)
        self.dir.cleanup()

    def commit(self):
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "change")

    def found(self):
        return check_migrations.violations("main")

    def test_a_clean_diff_passes(self):
        write(self.repo, "src/lib.rs", "fn main() { 1; }\n")
        self.commit()
        self.assertEqual(self.found(), [])

    def test_a_new_migration_passes_in_each_directory(self):
        write(self.repo, "migrations/0002_second.sql", "ALTER TABLE a ADD b int;\n")
        write(self.repo, "crates/orbyn-keyservice-server/migrations/0002_more.sql", "SELECT 1;\n")
        self.commit()
        self.assertEqual(self.found(), [])

    def test_a_modified_migration_fails_naming_the_file(self):
        write(self.repo, MIGRATION, "CREATE TABLE a (id bigint);\n")
        self.commit()
        problems = self.found()
        self.assertEqual(len(problems), 1)
        self.assertIn(MIGRATION, problems[0])
        self.assertIn("An applied migration is never edited. Add a new migration for the change.", problems[0])

    def test_a_modified_key_service_migration_fails(self):
        write(self.repo, KEYSERVICE, "CREATE TABLE log (id bigint);\n")
        self.commit()
        problems = self.found()
        self.assertEqual(len(problems), 1)
        self.assertIn(KEYSERVICE, problems[0])

    def test_a_deleted_migration_fails(self):
        os.remove(os.path.join(self.repo, MIGRATION))
        self.commit()
        problems = self.found()
        self.assertEqual(len(problems), 1)
        self.assertIn(MIGRATION, problems[0])
        self.assertIn("deleted", problems[0])

    def test_a_renamed_migration_fails_naming_both_paths(self):
        sh(self.repo, "mv", MIGRATION, "migrations/0001_renamed.sql")
        self.commit()
        problems = self.found()
        self.assertEqual(len(problems), 1)
        self.assertIn(MIGRATION, problems[0])
        self.assertIn("0001_renamed.sql", problems[0])

    def test_moving_a_migration_out_of_its_directory_fails(self):
        sh(self.repo, "mv", MIGRATION, "src/old.sql")
        self.commit()
        self.assertEqual(len(self.found()), 1)

    def test_a_mode_change_fails(self):
        os.chmod(os.path.join(self.repo, MIGRATION), 0o755)
        self.commit()
        problems = self.found()
        self.assertEqual(len(problems), 1)
        self.assertIn("mode", problems[0])

    def test_every_violation_is_listed_and_an_added_file_beside_it_is_not(self):
        write(self.repo, MIGRATION, "x\n")
        write(self.repo, KEYSERVICE, "y\n")
        write(self.repo, "migrations/0002_second.sql", "SELECT 1;\n")
        self.commit()
        self.assertEqual(len(self.found()), 2)

    def test_a_file_elsewhere_with_a_similar_name_is_not_a_migration(self):
        write(self.repo, "docs/migrations-guide.md", "text\n")
        write(self.repo, "src/lib.rs", "changed\n")
        self.commit()
        self.assertEqual(self.found(), [])

    def test_the_base_is_the_merge_base_so_main_moving_on_is_not_a_violation(self):
        sh(self.repo, "checkout", "-q", "main")
        write(self.repo, "migrations/0002_other.sql", "SELECT 2;\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "main moves on")
        sh(self.repo, "checkout", "-q", "change")
        write(self.repo, "src/lib.rs", "changed\n")
        self.commit()
        self.assertEqual(self.found(), [])

    def test_a_push_compares_with_the_previous_commit(self):
        sh(self.repo, "checkout", "-q", "main")
        write(self.repo, MIGRATION, "edited\n")
        sh(self.repo, "add", "-A")
        sh(self.repo, "commit", "-qm", "edit on main")
        self.assertEqual(len(check_migrations.violations("HEAD~1")), 1)

    def test_the_command_exits_1_with_the_message_and_0_when_clean(self):
        script = SCRIPT
        clean = subprocess.run(["python3", script, "--base", "main"], capture_output=True, text=True)
        self.assertEqual(clean.returncode, 0)
        write(self.repo, MIGRATION, "edited\n")
        self.commit()
        bad = subprocess.run(["python3", script, "--base", "main"], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn(MIGRATION, bad.stderr)
        self.assertIn("An applied migration is never edited. Add a new migration for the change.", bad.stderr)

    def test_a_base_commit_missing_from_the_checkout_is_a_clear_error(self):
        missing = "0123456789abcdef0123456789abcdef01234567"
        run = subprocess.run(["python3", SCRIPT, "--base", missing], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn(missing, run.stderr)
        self.assertIn("not in this checkout", run.stderr)
        self.assertIn("fetch-depth: 0", run.stderr)

    def test_a_missing_base_is_fetched_from_origin(self):
        # A clone holding only its newest commit, as a shallow CI checkout does, lacks the base.
        base = subprocess.run(["git", "rev-parse", "main"], cwd=self.repo, capture_output=True, text=True, check=True).stdout.strip()
        write(self.repo, MIGRATION, "edited\n")
        self.commit()
        with tempfile.TemporaryDirectory() as parent:
            clone = os.path.join(parent, "clone")
            subprocess.run(
                ["git", "clone", "-q", "--depth=1", "--no-tags", "--branch", "change", f"file://{self.repo}", clone],
                check=True,
                capture_output=True,
            )
            os.chdir(clone)
            self.assertNotEqual(
                subprocess.run(["git", "cat-file", "-e", f"{base}^{{commit}}"], capture_output=True).returncode, 0
            )
            self.assertEqual(len(check_migrations.violations(base)), 1)
            os.chdir(self.repo)

    def test_an_unknown_base_is_an_error_not_a_pass(self):
        script = SCRIPT
        run = subprocess.run(["python3", script, "--base", "nope"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)


if __name__ == "__main__":
    unittest.main()
