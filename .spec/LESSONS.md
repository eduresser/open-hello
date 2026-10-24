# LESSONS — maintained by the engine (`onp-spec lessons`)

> Do not edit by hand: any write from the engine overwrites this file.
> Canonical state in `.spec/lessons.json`; mutation only via `onp-spec lessons`.

## Confirmed — load in Specify/Design

Corroborated across multiple features. Apply as guidance.

_none_

## Candidates — under observation, do NOT apply yet

Seen in one feature only. Recorded, not trusted.

### L-001 — Simulate an unavailable dependency with a path that can never exist, not by hiding a tool, because installing the product puts the tool on the test host
- signal: `VERIFY_FAILED` · recurrence: 1 feature(s) · scope: `tests` · penalties: 0
- features: login-secret-release
- last evidence: AC-090 (login-secret-release, 2026-10-24T03:14:28.086Z)

### L-002 — A task that deletes files removes them from every task Files line in the same commit
- signal: `FILE_NOT_FOUND` · recurrence: 1 feature(s) · scope: `spec` · penalties: 0
- features: credential-login-v1b
- last evidence: T-050 (credential-login-v1b, 2026-10-24T03:14:28.122Z)

### L-003 — Tag each test with the criterion it proves, not a neighbouring one, and recheck tags when a test is copied from another
- signal: `AC_WITHOUT_TEST` · recurrence: 1 feature(s) · scope: `tests` · penalties: 0
- features: credential-login-v1b
- last evidence: AC-046 (credential-login-v1b, 2026-10-24T03:14:28.160Z)

## Quarantined — applied and failed, ignore

The failure came back even with the lesson applied. Reviewing it is up to the user.

_none_
