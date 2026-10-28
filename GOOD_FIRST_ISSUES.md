# Good first issues

These are seeded starter tasks. Each one is small, testable, and needs no network access.

1. Add a detector for Google API keys (AIza prefix, 35 characters after the prefix).
   Add the pattern, a unit test with a fake key, and a line in the README detector table.

2. Add an `--exclude` flag that takes a comma separated list of detector names to skip.
   Wire it through the CLI, cover it with a CLI test, and document it in the README.

3. Add a `--ignore-file` option that reads one regex per line and skips findings whose value matches any of them.
   Useful for known test fixtures. Add tests for matching and non matching values.

4. Report findings in JSON with a per file total when several files are passed on one command line.
   Keep single file output unchanged, add a multi file test, and update the README usage section.
