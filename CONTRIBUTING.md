# Contributing to shellbouncer

Thanks for helping make coding agents safer to use.

## Setup

```bash
git clone https://github.com/SaadRahman01/shellbouncer
cd shellbouncer
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

## The most useful contributions

1. **False positives.** A normal command that shellbouncer blocks or asks about. Add it to `ALLOW` in `tests/test_rules.py`, then fix the rule.
2. **Bypasses.** A dangerous command that gets through. Add it to `tests/test_edge_cases.py` (`BYPASS_ATTEMPTS`), then fix it. If it can't reasonably be fixed by reading the command, add it to `KNOWN_GAPS` instead and mention it in the README.
3. **New agents.** Adapters live in `src/shellbouncer/adapters.py` (payload → actions, verdict → output) and `src/shellbouncer/install.py` (settings file location). Link the agent's hook docs in your PR.

## Rules of thumb

- Zero runtime dependencies. Standard library only.
- `deny` is for things that are almost never right (destroying data, leaking secrets, running unknown code). Everything that is sometimes legitimate is `ask`.
- Error messages are read by both the human and the agent: say what the command would do, in plain words.
- Never make shellbouncer approve something on the user's behalf. "allow" means "no opinion".

## Reporting a security issue

Please don't open a public issue for a bypass that could hurt users right now. Use GitHub's private vulnerability reporting (Security tab → Report a vulnerability).
