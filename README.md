# Vault-Collector

Review-stage public page collector. No live collection or attestation acceptance has been demonstrated.

This repository contains only the generic collector, pinned dependency lock, offline lock check, action pin record and deliberately covered-button control. It contains no private checker, grading policy, case material, answer keys or credentials.

The manually dispatched `.github/workflows/collect.yml` captures a page with Playwright WebKit and iPhone 13 emulation, then attests the evidence in a separate job. Emulation does not establish real iPhone behavior. The workflow has no push or pull-request trigger. Capture, control, lock and workflow bytes are unchanged from reviewed collector candidate 3. Historical candidate warnings in source remain intentional until a separately approved live-run stage.

## Review and owner bootstrap

The owner is `@tarekvaultowner`; the builder account is separate. Keep owner login and recovery outside the assistants' environment.

Before merging, the owner must verify protection on `main`: pull request required, at least one approval, stale approvals dismissed, code-owner approval required, and no bypass (including administrators). Preserve any required signed-commit rule. Verify Actions defaults are read-only and outside-contributor workflow approval is required.

The new `.github/CODEOWNERS` is not effective on this first pull request because it is absent from the base branch. The owner must explicitly review and approve this bootstrap PR using the phone-only owner account, then merge only after the setup review is accepted. After merge, verify CODEOWNERS has no errors and the code-owner requirement applies to later changes. The protected flag alone does not verify these settings.

## Offline dependency check

`python3 tests/test_lock.py` checks the lock against the included public PyPI metadata snapshot. It installs nothing and does not prove runtime compatibility. The obsolete candidate-2 pin resolver is intentionally omitted; all six workflow action references already use reviewed full commit SHAs recorded in `ACTION-PINS.txt`.

## Before any controlled live demonstration

Merging and running require separate owner action after exact setup review. Record the merged main commit as external verifier authority, along with this repository, workflow path, main ref, expected run/attempt, trusted verifier binary and Sigstore root. Private verification material stays outside this public repository.

The planned demonstration uses one safe public page and the localhost broken control. It must verify actual evidence and attestations, confirm the good target is reachable and the covered button is rejected, and exercise the agreed negative controls. No token, secret or live-run instructions are supplied by this setup PR. A pull request or successful offline check is not live acceptance.
