# CI checks

## What runs

Compiles Python source (including any extensionless palette generator) without importing it, parses JSON/TOML, and syntax-checks shell scripts with bash -n or sh -n; runs all five existing in-memory patcher unit tests.

The workflow runs on every pull request (including docs-only edits), on pushes to `master`, and on manual dispatch. The tiny checks are cheaper than a separate change-routing system. The single, always-present **CI** job is the stable result; any failed step fails that check without paying for a second aggregate runner. No workflow-level path filter can leave the result pending.

## Run locally

```sh
python .github/check_static.py
python -m unittest -v test_juce8_megapatcher
```

## Coverage limits

Tests cover parsing/probing and non-mutation of in-memory input. They do not patch installed plugins or verify Wine/yabridge/DAW compatibility.

No build matrix, secrets, paid service, deployment, or dependency cache is needed. CI uses an explicit Ubuntu 24.04 image, short timeouts, read-only repository access, no persisted checkout credentials, immutable action commits, and cancellation of superseded validation runs. Runtime dependencies and application behavior are unchanged.

## Learning resources

- [GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)
- [Secure use of GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use)
- [Python unittest](https://docs.python.org/3/library/unittest.html)

Pin updates should be reviewed like code. A green syntax check is a useful minimum, not evidence of full product correctness.
