# Contributing

Thanks for your interest in contributing!

## Quick Start
1. Fork the repo and create a feature branch: `git checkout -b feat/my-change`.
2. Create a virtualenv and install deps: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`.
3. Run `python log_grok_parser.py -h` to see available options.
4. Add tests or example logs when fixing bugs.
5. Open a Pull Request with a clear description and before/after examples.

## Code Style
- Python 3.9+
- Keep the script single-file (CLI-first) and dependency-light.
- Favor small, composable functions.
- Document user-facing flags in the README.

## Commit Messages
- Use concise, imperative messages.
- Reference issues like `Fixes #123` when applicable.

## Adding Patterns
- Place Logstash-style `.grok` files under `patterns/custom/`.
- Keep one pattern per line: `NAME PATTERN`.
- For curated lists, add a `.json` file to `presets/` with pattern names in preference order.

## Reporting Bugs
Open an issue and include:
- OS and Python version
- py3grok version (`pip show py3grok`)
- Exact command used
- Sample of input log
- Patterns file snippet or preset list
- Error output or unexpected behavior