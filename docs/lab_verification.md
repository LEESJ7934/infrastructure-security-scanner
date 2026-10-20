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


## V7 independent configuration inspection (new, integration not live validated)

Apply `sql/migration_v7.sql` **only after backing up a V6 database**. This creates a new append-only `lab_verification_results` table; it never updates existing CVE rows. It has not yet been applied to an actual MySQL instance.

### Existing scan based dry-run

```powershell
py -m scripts.run_lab_verification --scan-id 1 --environment LOCAL_BASELINE --scope-file config/scope.local.json --dry-run
```

### Authorized FTP + HTTP + SSH checks

```powershell
py -m scripts.run_lab_verification --scan-id 1 --environment LOCAL_BASELINE --scope-file config/scope.local.json --allow-ftp-anonymous
```

Only current stored *open TCP* services are considered; the command does not create or re-run a port scan. Each found endpoint must match the existing approved scope file. The anonymous FTP attempt additionally needs an explicit flag. No upload, delete or directory enumeration is attempted.

Optional SSH admin evidence file (local, do **not** commit): `{"127.0.0.1:2222":{"pubkeyauthentication":true,"passwordauthentication":false}}`. Collect values with administrative authorization using `sshd -T` (account for Include/Match rules); an SSH greeting is never enough to infer the authentication policy.

The new records contain `execution_status` (`SUCCESS/ERROR/SKIPPED`) and independent `finding_status` (`CANDIDATE/POTENTIAL/CONFIRMED/NOT_DETECTED/INCONCLUSIVE`). `CONFIRMED` from FTP is confirmation **only of an anonymously accessible FTP configuration**, not a CVE. For SSH/HTTP, observations are preliminary when applicability cannot be proven. Unobserved or absent services are not marked safe. Snapshot/PDF and DVWA/Nuclei integration are not yet implemented.

**Limitations:** Mock tests, not live lab proof; configuration checks are not currently represented in the V6 JSON/PDF exporter. No EC2, SSM, MySQL, Nuclei or DVWA deployment was performed.
