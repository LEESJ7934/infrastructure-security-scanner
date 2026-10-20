# Controlled laboratory verification (work in progress)

This work does not assert access to any EC2 instance. **No live host, MySQL instance, DVWA or Nuclei verification has been run by this change.** No EC2 resources or AWS configuration have been changed.

## Current opt-in building blocks

- `verification.checker_ftp.FTPChecker(allow_anonymous_login=True)` tests **only** anonymous authentication, not file commands. Without opt-in it reads the greeting only. A successful anonymous login establishes a configuration fact, **not a CVE**.
- `verification.checker_http.HTTPChecker` compares an HTTP response against an intentionally limited header policy. It does not follow redirects, read the body, or turn a missing header into a CVE confirmation. Header applicability is context dependent.
- `verification.checker_ssh.SSHChecker` reads an SSH greeting. It cannot infer PasswordAuthentication from that banner; a boolean policy object must be obtained separately from authorized read-only admin information.

**Important:** These checkers are not wired into the legacy CVE dispatcher or database persistence. Their `details.finding_status` describes the configuration observation, distinct from the old CVE result `status`. They are not an operational end-to-end workflow.

## Remaining work

1. Add an explicit scope-authorized configuration-verification CLI with independent finding status and execution status, DB V7 migration and immutable evidence history.
2. Add Nuclei execution with pinning, reviewed template and target allowlists, JSONL validation and safe subprocess limits.
3. Add the DVWA session and non-destructive lab-only proof path, evidence redaction, request/response hashes, and regression tests.
4. Extend the consistent-snapshot JSON/PDF report with configuration findings and before/after snapshots.
5. With the operator: prepare isolated services on the **existing** EC2 using SSM/private networking. Never expose the lab to 0.0.0.0/0 or modify the operational SSH daemon.
6. Record independently verified live results and update Notion only after the evidence exists.

## Local offline tests

```bash
python -m unittest tests.test_lab_checkers -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

The unit tests use network mocks and do **not** establish a live FTP/SSH/HTTP verdict.
