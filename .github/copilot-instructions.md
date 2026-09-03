# Project Instructions

## Environment

- This is a Python project hosted on GitLab (not GitHub)
- Remote development via SSH to Rocky Linux 9
- Python 3.11+ with setuptools build system
- CI/CD via `.gitlab-ci.yml`

## Tool Usage Rules

- NEVER use terminal commands (cat, head, tail, less, grep) to read files that are in the workspace. Use the readFile tool instead.
- NEVER use `cat -A` or similar to inspect file contents. Use readFile.
- NEVER re-read a file you have already read in this session unless the file has been modified.
- Do not run bash commands to view file contents under any circumstances. The workspace tools have full access to all project files.
- When applying fixes, use the edit tools directly. Do not cat files to verify whitespace — trust the editor's representation.

## Code Style

- Follow PEP 8 and existing project conventions
- Use type hints on all function signatures
- Keep imports sorted: stdlib, third-party, local
- Use `from __future__ import annotations` where present

## YAML / CI

- `.gitlab-ci.yml` uses GitLab CI syntax, not GitHub Actions
- Use `needs` instead of `dependencies` for DAG mode
- Use `rules` instead of `only/except` (deprecated)
- Always include `policy: pull` on cache configurations for jobs that only read the cache
- Prefer parallel stages where jobs are independent

## Testing

- Tests are in the `tests/` directory
- Use pytest as the test runner
- Run tests with: `python -m pytest tests/`

## Git

- NEVER run any git commands. No commits, no pushes, no branch operations, no staging. The user manages git manually.
- Do not generate commit messages or suggest git operations.
