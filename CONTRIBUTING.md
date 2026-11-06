# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Read-only collectors.** A collector must never change anything on the system it reads.
  Prefer the smallest privilege set and document it in the README.
- **Permissive licences only.** New dependencies must be MIT, BSD, Apache-2.0 or similar.
  No GPL/AGPL code, no data sources that need a paid licence.
- **No copyrighted standard text.** Control descriptions are written in our own words. EU
  legal texts may be quoted; ISO/IEC standards may not.
- **Tests come with the change.** External systems are simulated with `httpx.MockTransport`
  (see `tests/test_wazuh.py`), so the suite runs without network access.

## Workflow

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q                       # must pass
shellcheck get.sh install.sh docker/entrypoint.sh packaging/build-deb.sh packaging/debian/*
```

CI runs the same checks on every pull request.

## Adding a collector

1. Create `app/collectors/<name>.py` with a class implementing `BaseCollector`
   (`is_configured`, `test_connection`, `collect`). Each check returns a `CheckResult`;
   a failing check must return `unknown`, never raise.
2. Register it in `evidence.get_collectors()`.
3. Point controls at it in `controls/*.yaml` with `automation: <name>:<check>`.
4. Add tests with a simulated API and document the required privileges.

## Adding a framework

Add `controls/<framework>.yaml` following `controls/nis2.yaml`. The file is validated at
start-up; `pytest` also checks that bundled catalogues load.

## Releases

Maintainers bump `APP_VERSION` in `app/config.py`, update `CHANGELOG.md` and push a tag
`vX.Y.Z`. GitHub Actions runs the tests, builds the `.deb` and publishes the release.
