# mini-X509-Linter

A from-scratch X.509 certificate linter in Rust, inspired by
[zlint](https://github.com/zmap/zlint). It parses a certificate and runs a registry of
focused lints drawn from three rule sources — **RFC 5280** (structural conformance),
the **CA/Browser Forum Baseline Requirements** (publicly-trusted TLS server rules), and a
set of pragmatic **hygiene** checks — then reports the findings in human-readable text or
machine-readable JSON.

The project is a Cargo workspace:

- `crates/linter/` — the library: certificate parsing facade, lint engine, and the rule
  registry. **No network access.**
- `crates/cli/` — the `mini-x509-lint` binary: argument parsing, input loading, output
  formatting, and exit-code logic.

> Scope note: this is a learning-oriented mini-linter, not a drop-in zlint replacement.
> See [Scope & limitations](#scope--limitations) for what it deliberately does *not* do.

## Installation & build

```sh
# Build the whole workspace (debug)
cargo build

# Build an optimized binary
cargo build --release
```

The binary is named **`mini-x509-lint`**:

- debug build: `target/debug/mini-x509-lint`
- release build: `target/release/mini-x509-lint`

## Running

Run via Cargo during development:

```sh
cargo run -p cli -- testdata/good.pem
```

…or invoke the built binary directly:

```sh
./target/debug/mini-x509-lint testdata/good.pem
```

The input may be a **PEM** or **DER** file; the format is auto-detected. A PEM file may
contain multiple certificates (see [`--chain`](#chain-linting)).

## CLI surface

```
mini-x509-lint [OPTIONS] <PATH>
```

`<PATH>` is the (required) path to a certificate file (PEM or DER, auto-detected).

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--format` | `text`, `json` | `text` | Output format. `text` is grouped by rule source; `json` is a nested array, one object per lint. |
| `--source` | comma-separated subset of `rfc5280`, `cabf_br`, `hygiene` | all | Restrict which rule sources run. |
| `--min-severity` | `notice`, `warn`, `error`, `fatal` | `notice` | Drop findings below this level at the reporting boundary (they are not shown and do not affect the exit code). |
| `--fail-on` | `notice`, `warn`, `error`, `fatal` | `error` | Exit non-zero if any *surfaced* finding is at or above this level. |
| `--chain` | (flag) | off | Lint **every** certificate in a PEM bundle, not just the first. |
| `--verbose`, `-v` | (flag) | off | Text only: list every lint individually (pass / `n/a` + `lint_id`) instead of the collapsed summary, and print a resolved `purpose:` header. |
| `--purpose` | `auto`, `tls-server`, `generic` | `auto` | Scope which sources apply based on the cert's intended purpose (see below). |
| `-h`, `--help` | | | Print help. |

Severity ordering, lowest to highest: **notice < warn < error < fatal**. There is no
explicit "pass" finding — a lint that finds nothing simply emits no findings, and a cert
with no findings at all prints `OK: no findings`.

### Report-everything behavior

The engine does **not** short-circuit. Every selected lint runs against the certificate
and all findings are collected, so a single run surfaces *all* problems at once rather than
stopping at the first. `--min-severity` then filters what is displayed, and `--fail-on`
decides the exit code from what remains. Output is deterministic (stable lint ordering, no
timestamps in the structure) so it is friendly to golden-file snapshots and diffs.

## Exit codes

Designed for CI pipelines and pre-commit hooks:

| Exit code | Meaning |
|-----------|---------|
| `0` | No surfaced finding was at or above `--fail-on`. |
| `1` | A surfaced finding was at or above `--fail-on`, **or** a load / parse / usage error occurred. |

Because the threshold is `--fail-on` (default `error`), a cert whose worst finding is a
`warn` exits `0` by default — the finding is still printed, it just does not fail the build.
Tighten the gate with `--fail-on warn` (or `notice`) as needed.

Example pre-commit / CI usage:

```sh
# Fail the build on any error-or-worse finding (default threshold)
mini-x509-lint certs/leaf.pem

# Stricter: fail on anything warn-or-worse, only consider warn+ findings at all
mini-x509-lint --fail-on warn --min-severity warn certs/leaf.pem
```

## Rule sources & the `--purpose` model

Lints are grouped into three sources:

- **`hygiene`** (4 lints) — `hygiene_not_expired`, `hygiene_no_sha1_signature`,
  `hygiene_rsa_key_min_2048`, `hygiene_ecdsa_curve_allowlist`.
- **`rfc5280`** (6 lints) — structural conformance: `rfc5280_version_is_v3`,
  `rfc5280_serial_number_positive`, `rfc5280_validity_not_after_after_not_before`,
  `rfc5280_basic_constraints_critical_on_ca`, `rfc5280_key_usage_present_when_ca`,
  `rfc5280_san_present_if_subject_empty`.
- **`cabf_br`** (4 lints) — CA/Browser Forum Baseline Requirements (TLS-server specific):
  `cabf_br_validity_max_398_days`, `cabf_br_cn_in_san`,
  `cabf_br_no_internal_names_or_reserved_ip`, `cabf_br_ext_key_usage_server_auth_present`.

### `--purpose`

The `cabf_br` rules are specific to **publicly-trusted TLS server** certificates. Applying
them to a certificate that was never meant to be a TLS server (for example a
key-encipherment-only or client-authentication cert that correctly omits the serverAuth
EKU) produces false positives. `--purpose` scopes which sources apply:

| `--purpose` | Sources run |
|-------------|-------------|
| `tls-server` | `rfc5280` + `hygiene` + `cabf_br` |
| `generic` | `rfc5280` + `hygiene` (skips `cabf_br`) |
| `auto` (default) | resolved **per certificate**: if the cert asserts the serverAuth EKU (OID `1.3.6.1.5.5.7.3.1`) it is treated as `tls-server`, otherwise as `generic`. |

So by default a non-TLS certificate does **not** trip the BR lints. `auto` is a heuristic;
`--purpose tls-server` forces the BR set even when serverAuth is absent (useful to assert
that a cert *should* have been a TLS server).

`--purpose` composes with `--source` as an **intersection**: the run is the overlap of the
purpose-allowed sources and the `--source` selection. For example
`--source cabf_br --purpose generic` runs nothing (empty intersection), and
`--purpose tls-server --source rfc5280` runs only `rfc5280`. Sources dropped by `--purpose`
are simply not run — they do not appear as `not_applicable` outcomes.

Reserved future values `client`, `smime`, and `code-signing` are documented but **not yet
implemented**.

## Examples

### A clean certificate (text)

```sh
$ mini-x509-lint testdata/good.pem
[rfc5280]
  (3 passed, 3 not applicable)
[cabf_br]
  (4 passed, 0 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
OK: no findings
summary: no findings
$ echo $?
0
```

### A certificate with a finding (text)

```sh
$ mini-x509-lint testdata/cabf_br_validity_400_days.pem
[rfc5280]
  (3 passed, 3 not applicable)
[cabf_br]
  error [cabf_br_validity_max_398_days] validity window is 400 days; CA/Browser Forum BR §6.3.2 allows at most 398 days for a subscriber certificate
  (3 passed, 0 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
summary: 1 error
$ echo $?
1
```

Finding lines have the shape `  <severity> [<lint_id>] <message>`. The trailing
`summary:` line aggregates counts by severity (e.g. `1 error`), or `no findings`.

An expired cert is a `warn`, so by default it prints the finding but still exits `0`:

```sh
$ mini-x509-lint testdata/expired.pem
[rfc5280]
  (3 passed, 3 not applicable)
[cabf_br]
  (4 passed, 0 not applicable)
[hygiene]
  warn [hygiene_not_expired] certificate expired: notAfter is 1717200000 (Unix seconds), now is <current time>
  (2 passed, 1 not applicable)
summary: 1 warn
$ echo $?            # 0 — warn is below the default --fail-on=error
0
$ mini-x509-lint --fail-on warn testdata/expired.pem >/dev/null; echo $?
1
```

### JSON output

```sh
$ mini-x509-lint --format json testdata/expired.pem
```

JSON is a flat array of lint-outcome objects, each carrying its `lint_id`, `source`,
`applicability` (`applies` / `not_applicable`), and a `findings` array of
`{severity, message}` objects (empty when the lint passed):

```json
[
  {
    "lint_id": "hygiene_not_expired",
    "source": "hygiene",
    "applicability": "applies",
    "findings": [
      {
        "severity": "warn",
        "message": "certificate expired: notAfter is 1717200000 (Unix seconds), now is 1781718900"
      }
    ]
  },
  {
    "lint_id": "hygiene_no_sha1_signature",
    "source": "hygiene",
    "applicability": "applies",
    "findings": []
  }
]
```

`--format json` always emits every lint with its `lint_id`/`applicability`; `--verbose`
does not affect JSON.

### Verbose text

```sh
$ mini-x509-lint --verbose testdata/good.pem
purpose: tls-server (auto)
[rfc5280]
  n/a   rfc5280_basic_constraints_critical_on_ca
  n/a   rfc5280_key_usage_present_when_ca
  n/a   rfc5280_san_present_if_subject_empty
  pass  rfc5280_serial_number_positive
  pass  rfc5280_validity_not_after_after_not_before
  pass  rfc5280_version_is_v3
[cabf_br]
  pass  cabf_br_cn_in_san
  pass  cabf_br_ext_key_usage_server_auth_present
  pass  cabf_br_no_internal_names_or_reserved_ip
  pass  cabf_br_validity_max_398_days
[hygiene]
  n/a   hygiene_ecdsa_curve_allowlist
  pass  hygiene_no_sha1_signature
  pass  hygiene_not_expired
  pass  hygiene_rsa_key_min_2048
OK: no findings
summary: no findings
```

The header reports the resolved purpose and whether it came from `auto`. Within each source
group, lints are listed in stable `lint_id` order with a `pass` / `n/a` status token.

### `--purpose generic`

A certificate that omits the serverAuth EKU is treated as `generic` under the default
`auto`, so the `cabf_br` source is skipped entirely and no BR false positive is reported:

```sh
$ mini-x509-lint --purpose generic testdata/cabf_br_missing_serverauth.pem
[rfc5280]
  (3 passed, 3 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
OK: no findings
summary: no findings
```

Forcing `--purpose tls-server` on the same cert runs the BR set and surfaces the missing
EKU as an `error`:

```sh
$ mini-x509-lint --purpose tls-server testdata/cabf_br_missing_serverauth.pem
...
[cabf_br]
  error [cabf_br_ext_key_usage_server_auth_present] certificate does not assert the serverAuth Extended Key Usage (OID 1.3.6.1.5.5.7.3.1); CA/Browser Forum BR §7.1.2.7 requires it for TLS server certificates
  (3 passed, 0 not applicable)
...
$ echo $?
1
```

### `--chain` (PEM bundle)

With `--chain`, every certificate in a PEM bundle is linted and reported under a labelled
header (`Certificate 1 (leaf)`, `Certificate 2`, …). The run fails (`exit 1`) if **any**
certificate trips `--fail-on`:

```sh
$ mini-x509-lint --chain bundle.pem
Certificate 1 (leaf)
[rfc5280]
  (3 passed, 3 not applicable)
[cabf_br]
  (4 passed, 0 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
OK: no findings

Certificate 2
[rfc5280]
  (3 passed, 3 not applicable)
[cabf_br]
  (4 passed, 0 not applicable)
[hygiene]
  warn [hygiene_not_expired] certificate expired: notAfter is 1717200000 (Unix seconds), now is <current time>
  (2 passed, 1 not applicable)
summary: 1 warn
```

Without `--chain`, only the first certificate in the bundle is linted.

## Scope & limitations

This is a deliberately small linter; be aware of the boundaries:

- **Each certificate is linted independently.** `--chain` parses and lints every cert in a
  bundle separately — there are **no chain-aware lints** (no path-building, no
  issuer/subject linkage checks, no signature verification against the issuer). Full
  chain validation is out of scope.
- **The CA/Browser Forum BR lints are simplified.** They implement a focused subset of the
  Baseline Requirements (validity window, CN-in-SAN, internal/reserved names, serverAuth
  EKU presence), not the full specification.
- **No network access.** The `linter` crate never touches the network. Fetching a
  certificate from a live host (`--from-host` / `--sni` / `--timeout`) is planned for a
  separate `fetch` feature and is **not** available in this version.
- Reserved `--purpose` values (`client`, `smime`, `code-signing`) are not implemented.

## Development

```sh
cargo test                                   # run all tests
cargo clippy --all-targets -- -D warnings    # lint
cargo fmt --check                            # formatting
cargo audit                                  # dependency advisories
```
