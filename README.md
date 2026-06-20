# mini-X509-Linter

mini-X509-Linter is a from-scratch X.509 certificate linter written in Rust and inspired by
[zlint](https://github.com/zmap/zlint). It parses a certificate, runs a registry of **70**
per-certificate lints, and reports what it finds as human-readable text or machine-readable JSON.
The per-cert lints are drawn from seven rule sources: **RFC 5280** structural conformance, a set of
**post-quantum (PQC)** algorithm checks (ML-DSA / SLH-DSA signatures and ML-KEM key encapsulation),
the four **CA/Browser Forum** profiles (**Baseline
Requirements**, **Extended Validation**, **Code Signing**, and **S/MIME**), and a set of
pragmatic **hygiene** checks. On top of those, an eighth **`chain`** source runs **chain-aware**
checks across a certificate chain (issuer↔subject linkage, AKI↔SKI matching, pathLen, validity
nesting, and — with the `verify` feature — cryptographic signature verification of each cert against
its issuer, classical and post-quantum).

Beyond plain file linting, the tool can fetch a certificate straight from a live host over TLS,
print a detailed inspection summary of a certificate's own fields (including post-quantum
algorithms), and lint every certificate in a chain bundle. It is designed to drop cleanly into
CI pipelines and pre-commit hooks: output is deterministic, the exit code is driven by a
configurable severity threshold, and the engine never short-circuits, so a single run surfaces
every problem at once.

The project is a Cargo workspace with a deliberate separation between the network-free lint
engine and the optional live-fetch capability:

- **`crates/linter/`** — the library: the certificate-parsing facade, the lint engine, and the
  rule registry. It has **no network access** and no I/O beyond reading the bytes it is handed.
- **`crates/fetch/`** — a standalone crate that performs a blocking TLS handshake to retrieve a
  certificate chain from a live host. All `rustls`/network dependencies live here, and it does
  **not** depend on `linter`. The CLI uses it only through an opt-in `fetch` cargo feature.
- **`crates/cli/`** — the `mini-x509-lint` binary: argument parsing, input loading, the text and
  JSON renderers, the inspection summary, and the exit-code logic.

> **Scope note.** This is a learning-oriented mini-linter, not a drop-in zlint replacement. See
> [Scope & limitations](#scope--limitations) for what it deliberately does *not* do.

## Installation & build

Building the whole workspace produces the network-free linter and the default CLI:

```sh
cargo build              # debug build of the whole workspace
cargo build --release    # optimized binary
```

Fetching a certificate from a live host is gated behind an **opt-in** `fetch` cargo feature
that is **not** part of the default feature set — ordinary file linting needs nothing extra.
Build with the feature only when you want live retrieval:

```sh
cargo build -p cli --features fetch
```

Cryptographic chain **signature verification** (`chain_signature_valid`) lives behind a `verify`
cargo feature on the `linter` crate. The **CLI enables it by default**, so `mini-x509-lint --chain`
verifies signatures out of the box — its pure-Rust crypto deps (`ring` for RSA/ECDSA/Ed25519,
`fips204`/`fips205` for ML-DSA/SLH-DSA; no OpenSSL/C toolchain) come in only via the CLI. The
`linter` **library** keeps `verify` opt-in so library consumers stay dependency-light; the other
seven chain lints are structural and need no crypto, so they run without the feature.

The binary is named **`mini-x509-lint`** and lands at `target/debug/mini-x509-lint` (or
`target/release/mini-x509-lint` for a release build).

## Running

During development you can run through Cargo, or invoke the built binary directly:

```sh
cargo run -p cli -- testdata/good.pem
./target/debug/mini-x509-lint testdata/good.pem
```

The input may be a **PEM** or **DER** file; the format is auto-detected. A PEM file may contain
multiple certificates — by default only the first (the leaf) is linted, and
[`--chain`](#linting-a-chain--bundle---chain) opts into linting every certificate in the bundle.

## CLI surface

```
mini-x509-lint [OPTIONS] <PATH>
mini-x509-lint [OPTIONS] --from-host <HOST[:PORT]>   # requires --features fetch
```

The input is **either** a positional `<PATH>` (a PEM or DER certificate file) **or**
`--from-host`. The two are mutually exclusive, and exactly one must be supplied.

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `--format` | `text`, `json` | `text` | Output format. `text` is grouped by rule source; `json` is one object per lint outcome. |
| `--source` | comma-separated subset of `rfc5280`, `pqc`, `cabf_br`, `cabf_ev`, `cabf_cs`, `cabf_smime`, `hygiene`, `chain` | all | Restrict which rule sources run. (`chain` only produces output under `--chain` / `--from-host`.) |
| `--min-severity` | `notice`, `warn`, `error`, `fatal` | `notice` | Drop findings below this level at the reporting boundary (not shown, no effect on the exit code). |
| `--fail-on` | `notice`, `warn`, `error`, `fatal` | `error` | Exit non-zero if any *surfaced* finding is at or above this level. |
| `--chain` | (flag) | off | Lint **every** certificate in a PEM bundle, not just the first. |
| `--info` | (flag) | off | Print a certificate **summary** block before the lint report (long-only; see [Inspecting a certificate](#inspecting-a-certificate---info)). |
| `--verbose`, `-v` | (flag) | off | Text only: list every lint individually (`pass` / `n/a` + `lint_id`) instead of the collapsed per-source summary, and print a resolved `purpose:` header. |
| `--purpose` | `auto`, `tls-server`, `code-signing`, `smime`, `generic` | `auto` | Scope which sources apply based on the certificate's intended purpose (see [the `--purpose` model](#the---purpose-model)). |
| `--from-host` | `host[:port]` | — | *(requires `--features fetch`)* Fetch the certificate from a live host over TLS instead of reading a file (default port `443`). |
| `--sni` | name | derived | *(requires `--features fetch`)* SNI to send in the handshake. **Required** for an IP target; derived from a hostname otherwise, and overridable. |
| `--timeout` | seconds | `10` | *(requires `--features fetch`)* Connection + handshake timeout for `--from-host`. |
| `--save` | `path` | — | *(requires `--features fetch`)* Write the full presented chain to `<path>` as a PEM bundle. Only valid with `--from-host`; refuses to overwrite unless `--force`. |
| `--force` | (flag) | off | *(requires `--features fetch`)* Allow `--save` to overwrite an existing file. |
| `--block-private` | (flag) | off | *(requires `--features fetch`)* Opt-in SSRF guard: refuse `--from-host` targets that resolve to private / loopback / link-local addresses. |
| `-h`, `--help` | | | Print help. |

Severities are ordered, lowest to highest, as **notice < warn < error < fatal**. There is no
explicit "pass" finding: a lint that finds nothing simply emits no findings, and a certificate
with no findings at all prints `OK: no findings`.

### Report-everything behavior

The engine does **not** short-circuit. Every selected lint runs against the certificate and all
findings are collected, so one run surfaces *all* problems rather than stopping at the first.
`--min-severity` then filters what is displayed, and `--fail-on` decides the exit code from what
remains. Output is deterministic — stable lint ordering and no timestamps in the structure — so
it is friendly to golden-file snapshots and diffs.

## Exit codes

The exit code is designed for CI pipelines and pre-commit hooks:

| Exit code | Meaning |
|-----------|---------|
| `0` | No surfaced finding was at or above `--fail-on`. |
| `1` | A surfaced finding was at or above `--fail-on`, **or** a load / parse / usage error occurred. |

Because the threshold defaults to `error`, a certificate whose worst finding is a `warn` exits
`0` by default — the finding is still printed, it just does not fail the build. Tighten the gate
with `--fail-on warn` (or `notice`) when you want warnings to break CI:

```sh
# Fail on any error-or-worse finding (default threshold)
mini-x509-lint certs/leaf.pem

# Stricter: fail on anything warn-or-worse, and only consider warn+ findings at all
mini-x509-lint --fail-on warn --min-severity warn certs/leaf.pem
```

## Rule sources & lints

The **70 per-certificate lints** are grouped into seven sources, plus an eighth **`chain`** source
of **8 chain-aware lints** (see [Linting a chain](#linting-a-chain--bundle---chain)). Each lint
declares its source, so `--source` selects them by group and the text report groups findings the same
way. The counts and a representative sample of each group:

- **`rfc5280`** (16) — structural conformance to RFC 5280: e.g. `rfc5280_version_is_v3`,
  `rfc5280_serial_number_positive`, `rfc5280_validity_not_after_after_not_before`,
  `rfc5280_basic_constraints_critical_on_ca`, `rfc5280_key_usage_present_when_ca`,
  `rfc5280_ext_authority_key_identifier_no_key_identifier`, `rfc5280_utc_time_not_in_zulu`.
- **`pqc`** (9) — post-quantum algorithm checks. Five for the ML-DSA (FIPS 204) and SLH-DSA
  (FIPS 205) **signature** families: `pqc_algorithm_known`, `pqc_spki_parameters_absent`,
  `pqc_signature_parameters_absent`, `pqc_public_key_length`, `pqc_key_usage_consistency` (which
  also rejects encryption/key-agreement bits — `keyEncipherment`, `keyAgreement`,
  `dataEncipherment`, `encipherOnly`, `decipherOnly` — on a signature-only key). Four more for the
  ML-KEM (FIPS 203) **key-encapsulation** family, the mirror image of the signature rules:
  `pqc_mlkem_algorithm_known`, `pqc_mlkem_spki_parameters_absent`, `pqc_mlkem_public_key_length`,
  and `pqc_mlkem_key_usage_consistency` (a KEM key permits `keyEncipherment` / `keyAgreement` and
  forbids the signing bits `digitalSignature` / `keyCertSign` / `cRLSign`).
- **`cabf_br`** (12) — CA/Browser Forum Baseline Requirements for publicly-trusted TLS servers:
  e.g. `cabf_br_validity_max_398_days`, `cabf_br_cn_in_san`,
  `cabf_br_no_internal_names_or_reserved_ip`, `cabf_br_ext_key_usage_server_auth_present`,
  `cabf_br_dnsname_bad_character_in_label`, `cabf_br_subject_country_not_iso`.
- **`cabf_ev`** (9) — CA/Browser Forum Extended Validation requirements (folded into the
  TLS-server profile, self-gated on an EV policy OID): e.g. `cabf_ev_organization_name_missing`,
  `cabf_ev_business_category_invalid`, `cabf_ev_jurisdiction_country_missing`,
  `cabf_ev_not_wildcard`, `cabf_ev_validity_max_398_days`.
- **`cabf_cs`** (8) — CA/Browser Forum Code Signing Baseline Requirements (gated on the
  codeSigning EKU): e.g. `cabf_cs_eku_required`, `cabf_cs_rsa_key_size`,
  `cabf_cs_validity_period_longer_than_39_months`, `cabf_cs_authority_information_access`.
- **`cabf_smime`** (12) — CA/Browser Forum S/MIME Baseline Requirements (gated on the
  emailProtection EKU): e.g. `cabf_smime_san_present`, `cabf_smime_email_in_san`,
  `cabf_smime_single_email_subject`, `cabf_smime_eku_no_server_auth`,
  `cabf_smime_crl_distribution_points_http`.
- **`hygiene`** (4) — pragmatic, profile-independent best-practice checks:
  `hygiene_not_expired`, `hygiene_no_sha1_signature`, `hygiene_rsa_key_min_2048`,
  `hygiene_ecdsa_curve_allowlist`.
- **`chain`** (8) — cross-certificate checks run over a chain (only under `--chain` / `--from-host`,
  see below): `chain_subject_issuer_dn_match`, `chain_not_in_order`, `chain_issuer_not_in_chain`,
  `chain_aki_ski_match`, `chain_issuer_is_ca`, `chain_path_len_respected`, `chain_validity_nested`,
  and `chain_signature_valid` (the last only with the `verify` feature — on by default in the CLI).

Most lints self-gate via an *applicability* check: a lint that does not apply to a given
certificate (a CA-only rule on a leaf, a code-signing rule on a TLS cert, a PQC rule on an RSA
key) reports `not_applicable` rather than a finding. The PQC source is *universal* — it runs
under every purpose and simply reports `not_applicable` on non-PQC keys — which is why an
ordinary RSA certificate still shows a `[pqc]` group with everything not applicable.

## The `--purpose` model

The profile-specific sources are only meaningful for certificates of a matching kind: the
`cabf_br`/`cabf_ev` rules target publicly-trusted **TLS server** certificates, `cabf_cs` targets
**code-signing** certificates, and `cabf_smime` targets **S/MIME** certificates. Applying the BR
rules to, say, a client-authentication certificate that correctly omits the serverAuth EKU would
produce false positives. `--purpose` scopes which sources run so that does not happen:

| `--purpose` | Sources run |
|-------------|-------------|
| `tls-server` | `rfc5280` + `pqc` + `hygiene` + `cabf_br` + `cabf_ev` |
| `code-signing` | `rfc5280` + `pqc` + `hygiene` + `cabf_cs` |
| `smime` | `rfc5280` + `pqc` + `hygiene` + `cabf_smime` |
| `generic` | `rfc5280` + `pqc` + `hygiene` (skips the profile-specific sources) |
| `auto` (default) | resolved **per certificate** from its EKU: codeSigning → `code-signing`, else serverAuth (OID `1.3.6.1.5.5.7.3.1`) → `tls-server`, else emailProtection → `smime`, otherwise → `generic`. |

Under the default `auto`, a certificate that is not a TLS server simply never trips the BR lints.
`auto` is a heuristic; passing `--purpose tls-server` explicitly forces the BR/EV set even when
serverAuth is absent, which is useful to assert that a certificate *should* have been a TLS
server.

`--purpose` composes with `--source` as an **intersection**: the run is the overlap of the
purpose-allowed sources and the `--source` selection. So `--source cabf_br --purpose generic`
runs nothing (empty intersection), and `--purpose tls-server --source rfc5280` runs only
`rfc5280`. Sources dropped by `--purpose` are simply not run — they do not appear as
`not_applicable` outcomes. The `client` purpose is reserved as a planned future value and
currently behaves like `generic`.

## Examples

### A clean certificate

```sh
$ mini-x509-lint testdata/good.pem
[rfc5280]
  (7 passed, 9 not applicable)
[pqc]
  (0 passed, 5 not applicable)
[cabf_br]
  (12 passed, 0 not applicable)
[cabf_ev]
  (0 passed, 9 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
OK: no findings
summary: no findings
$ echo $?
0
```

This is an RSA TLS leaf, so `auto` resolves it to `tls-server`: the `rfc5280`, `pqc`, `cabf_br`,
`cabf_ev`, and `hygiene` groups run, while `cabf_cs` and `cabf_smime` are out of profile and do
not appear. The `[pqc]` and `[cabf_ev]` groups show everything not applicable — expected for a
non-PQC, non-EV certificate.

### A certificate with a finding

```sh
$ mini-x509-lint testdata/cabf_br_validity_400_days.pem
[rfc5280]
  (7 passed, 9 not applicable)
[pqc]
  (0 passed, 5 not applicable)
[cabf_br]
  error [cabf_br_validity_max_398_days] validity window is 400 days; CA/Browser Forum BR §6.3.2 allows at most 398 days for a subscriber certificate
  (11 passed, 0 not applicable)
[cabf_ev]
  (0 passed, 9 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
summary: 1 error
$ echo $?
1
```

Finding lines have the shape `  <severity> [<lint_id>] <message>`, and the trailing `summary:`
line aggregates counts by severity (here `1 error`), or reads `no findings`. An expired
certificate trips `hygiene_not_expired` at `warn`, so by default it prints the finding but still
exits `0`; tighten the gate with `--fail-on warn` to make it fail.

### JSON output

```sh
$ mini-x509-lint --format json testdata/expired.pem
```

JSON is a flat array of lint-outcome objects, each carrying its `lint_id`, `source`,
`applicability` (`applies` / `not_applicable`), and a `findings` array of `{severity, message}`
objects (empty when the lint passed):

```json
[
  {
    "lint_id": "hygiene_not_expired",
    "source": "hygiene",
    "applicability": "applies",
    "findings": [
      { "severity": "warn", "message": "certificate expired: notAfter is 1717200000 (Unix seconds), now is 1781718900" }
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

`--format json` always emits every lint with its `lint_id`/`applicability`; `--verbose` does not
affect JSON.

### Verbose text

`--verbose` lists every lint individually, in stable `lint_id` order within each source group,
with a `pass` / `n/a` status token, and prepends a header reporting the resolved purpose:

```sh
$ mini-x509-lint --verbose testdata/good.pem
purpose: tls-server (auto)
[rfc5280]
  n/a   rfc5280_basic_constraints_critical_on_ca
  pass  rfc5280_ext_key_usage_without_bits
  pass  rfc5280_serial_number_positive
  pass  rfc5280_version_is_v3
  ... (16 rfc5280 lints, in lint_id order) ...
[pqc]
  n/a   pqc_algorithm_known
  ... (9 pqc lints, all n/a on an RSA key) ...
[cabf_br]
  pass  cabf_br_cn_in_san
  ... (12 cabf_br lints) ...
[cabf_ev]
  n/a   cabf_ev_organization_name_missing
  ... (9 cabf_ev lints, all n/a without an EV policy OID) ...
[hygiene]
  pass  hygiene_not_expired
  ... (4 hygiene lints) ...
OK: no findings
summary: no findings
```

### `--purpose generic`

A certificate that omits the serverAuth EKU resolves to `generic` under the default `auto`, so
the `cabf_br`/`cabf_ev` sources are skipped entirely and no BR false positive is reported.
Forcing `--purpose tls-server` on the same certificate runs the BR set and surfaces the missing
EKU as an `error`:

```sh
$ mini-x509-lint --purpose tls-server testdata/cabf_br_missing_serverauth.pem
...
[cabf_br]
  error [cabf_br_ext_key_usage_server_auth_present] certificate does not assert the serverAuth Extended Key Usage (OID 1.3.6.1.5.5.7.3.1); CA/Browser Forum BR §7.1.2.7 requires it for TLS server certificates
  (11 passed, 0 not applicable)
...
$ echo $?
1
```

## Inspecting a certificate (`--info`)

`--info` prints a deterministic **summary block** of the certificate's own fields — version,
serial, subject and issuer DN, validity window, signature algorithm, public key,
BasicConstraints, KeyUsage bits, ExtendedKeyUsage purposes, SubjectKeyIdentifier,
AuthorityKeyIdentifier (its `keyIdentifier`), and SubjectAltName — and then **still runs the
lint report**
below it. It never suppresses linting and never changes the exit code, so it is purely additive;
omitting it leaves the output byte-for-byte unchanged.

```sh
$ mini-x509-lint --info testdata/good.pem
Certificate Summary
  Version:             v3
  Serial:              11
  Subject:             CN=good.example.com
  Issuer:              CN=good.example.com
  Not Before:          Jun  1 00:00:00 2026 +00:00
  Not After:           Jun  1 00:00:00 2027 +00:00
  Signature Algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
  Public Key:          rsaEncryption (1.2.840.113549.1.1.1), 2048 bits
  Basic Constraints:   CA:false (not critical)
  Key Usage:           (not present)
  Extended Key Usage:  serverAuth (not critical)
  Subject Key Id:      1D:33:53:BC:F1:E7:31:96:F9:67:D2:FC:72:0A:F0:96:7D:2F:4C:13
  Authority Key Id:    (not present)
  Subject Alt Name:    DNS:good.example.com (not critical)

[rfc5280]
  (7 passed, 9 not applicable)
... (the normal lint report follows) ...
```

The summary degrades gracefully on anything it cannot read, and it is **post-quantum aware**:
even when `oid-registry` does not recognize a PQC algorithm OID, the summary still shows a
human-readable name alongside the raw OID. Inspecting the bundled SLH-DSA root CA:

```sh
$ mini-x509-lint --info testdata/slh_dsa_root_ca.pem
Certificate Summary
  Version:             v3
  Serial:              01:2D
  Subject:             CN=SLH-DSA Test Root, C=SE, O=mini-x509-linter testdata
  Issuer:              CN=SLH-DSA Test Root, C=SE, O=mini-x509-linter testdata
  Not Before:          Jan  1 00:00:00 2026 +00:00
  Not After:           Jan  1 00:00:00 2126 +00:00
  Signature Algorithm: SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)
  Public Key:          SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)
  Basic Constraints:   CA:true (critical)
  Key Usage:           Certificate Sign, CRL Sign (critical)
  Extended Key Usage:  (not present)
  Subject Key Id:      3C:B2:20:74:AC:49:56:3D:94:72:6C:9A:22:9A:66:DD:51:70:10:01
  Authority Key Id:    3C:B2:20:74:AC:49:56:3D:94:72:6C:9A:22:9A:66:DD:51:70:10:01
  Subject Alt Name:    DNS:slh-dsa-test-root (not critical)

[rfc5280]
  ...
```

With `--format json`, `--info` wraps the report as `{ "summary": { … }, "lints": [ … ] }`, where
`lints` is exactly the array described under [JSON output](#json-output).

Without `--chain`, `--info` summarizes only the first (leaf) certificate. Combine it with
`--chain` to get a summary for every certificate in a bundle (see below).

## Linting a chain / bundle (`--chain`)

With `--chain`, every certificate in a PEM bundle is linted and reported under a labelled header
(`Certificate 1 (leaf)`, `Certificate 2`, …). The run fails (`exit 1`) if **any** certificate
trips `--fail-on`. Without `--chain`, only the first certificate is linted.

```sh
$ mini-x509-lint --chain bundle.pem
Certificate 1 (leaf)
[rfc5280]
  (7 passed, 9 not applicable)
... (groups) ...
OK: no findings

Certificate 2
[rfc5280]
  ...
summary: 1 warn
```

### Chain-aware checks (the `chain` source)

Beyond linting each certificate independently, `--chain` also runs the **`chain`** source over the
bundle as a whole and appends a `Chain checks:` section. It first **builds the chain by issuer↔subject
linkage** (byte-exact Name DER, confirmed by AKI↔SKI) — so the order of the certs in the file does
**not** matter; a shuffled bundle is reordered and reported with a `chain_not_in_order` **Notice**
rather than spurious errors. It then checks each link: issuer/subject linkage, AKI↔SKI match,
issuer-is-a-CA, `pathLenConstraint`, validity nesting, and — with the `verify` feature (on by default
in the CLI) — **cryptographic signature verification** of each certificate against its issuer's key
(RSA/ECDSA/Ed25519 via `ring`; ML-DSA/SLH-DSA via `fips204`/`fips205`; an unsupported algorithm yields
a `Notice`, never a false error). Chain findings fold into the exit code like any other.

```sh
$ mini-x509-lint --chain valid-chain.pem
Certificate 1 (leaf)
... per-cert reports ...
Certificate 3
OK: no findings
summary: no findings

Chain checks:
Certificate 1 (leaf) → Certificate 2
  (no findings)
Certificate 2 → Certificate 3
  (no findings)
```

A **broken** chain — a missing intermediate, an unrelated cert, a wrong issuer, or a bad signature —
is reported (and fails the run). When the bundle doesn't form a single chain, the construction
findings appear under a `(whole chain)` heading:

```sh
$ mini-x509-lint --chain missing-intermediate.pem ; echo "exit=$?"
...
Chain checks:
(whole chain)
  error [chain_subject_issuer_dn_match] certificate 1 (CN=leaf.example.com) links to no issuer in the presented set (missing middle link / broken chain)
  error [chain_subject_issuer_dn_match] certificate 2 (CN=Root CA) does not link into the presented chain (unlinkable / extra certificate)
exit=1
```

In JSON the chain results appear in a top-level `chain` array (one entry per link, or a
`{ "scope": "chain", … }` entry for whole-chain construction findings) alongside the existing
per-cert structure.

> **Trust vs. linting.** The chain source verifies the **soundness of the links that are present** —
> it does **not** do trust-anchor / path validation against a root store, and it does not check
> revocation. (For `--from-host`, anchoring to a trusted root is reported separately by the
> `verification:` verdict.) See [Scope & limitations](#scope--limitations).

Combining `--chain` with `--info` prints a summary block for **every** certificate in the
bundle, each under the same `Certificate N` label, before the chain lint report:

```sh
$ mini-x509-lint --chain --info bundle.pem
Certificate 1 (leaf)
Certificate Summary
  Version:             v3
  Subject:             CN=leaf.example.com
  ...

Certificate 2
Certificate Summary
  Version:             v3
  Subject:             CN=Intermediate CA
  ...

Certificate 1 (leaf)
[rfc5280]
  ...
```

In JSON, `--chain --info` emits `{ "certificates": [ { "certificate": "<label>", "summary": { … },
"outcomes": [ … ] }, … ] }` — one entry per certificate, each pairing its summary with its lint
outcomes.

## Fetching from a host

Instead of reading a file, the CLI can retrieve a certificate directly from a live host over a
TLS handshake with `--from-host`. This capability is gated behind the opt-in `fetch` cargo
feature (see [Installation & build](#installation--build)); file linting works without it.

```sh
cargo run -p cli --features fetch -- --from-host example.com
```

`--from-host` takes `host[:port]` and defaults to port `443`. It is mutually exclusive with the
positional `<PATH>` — choose exactly one input source. For a **hostname** target the SNI is
derived from the host by default and `--sni <name>` overrides it; for an **IP** target the SNI
cannot be derived, so `--sni` is **required** and the run errors clearly if it is missing.
`--timeout <secs>` (default `10`) bounds the connection and handshake.

Only the **leaf** certificate is linted by the per-cert sources — it flows into the same engine and
produces the same findings as a file input. The intermediates the server presents are displayed as
chain context, and alongside the findings the output shows a separate chain **verification verdict**
(`verification: valid` or `verification: invalid: <reason>`). The verdict and the findings are
distinct: the verdict is the result of validating the presented chain against a trusted root store,
whereas the findings are the leaf's lint results.

The [chain-aware checks](#chain-aware-checks-the-chain-source) also run over the presented chain (leaf
+ intermediates), appending the same `Chain checks:` section. Because servers usually send the leaf and
intermediates but **not** the root (the client holds it in its trust store), the top link gets a
`chain_issuer_not_in_chain` **Notice** rather than an error — trust *to* the root is what the
`verification:` verdict covers, separately.

```sh
$ cargo run -p cli --features fetch -- --from-host example.com
presented chain:
  Certificate 1 (leaf) example.com
  Certificate 2 Example Intermediate CA
verification: valid

[rfc5280]
  (7 passed, 9 not applicable)
[pqc]
  (0 passed, 5 not applicable)
[cabf_br]
  (12 passed, 0 not applicable)
[cabf_ev]
  (0 passed, 9 not applicable)
[hygiene]
  (3 passed, 1 not applicable)
OK: no findings
summary: no findings
```

A host presenting an expired or otherwise untrusted certificate still yields the captured chain
plus a `verification: invalid: <reason>` line, and the leaf's lint findings are reported exactly
as for a file input.

> **Security note.** The handshake uses an accept-any verifier whose *only* purpose is to capture
> the presented chain, so that untrusted / expired / self-signed certificates can still be
> inspected. It still verifies that the peer holds the private key; only the chain-of-trust
> decision is deferred to a **separate, real** verification pass against a root store. Capturing
> the chain and judging it are two independent steps. The handshake uses the `ring` crypto
> provider. `--block-private` opts into an SSRF guard that refuses targets resolving to private /
> loopback / link-local addresses; it is **off by default** because this is a local CLI meant for
> validating your own / internal hosts.

### Saving the presented chain (`--save` / `--force`)

`--save <path>` writes the **full presented chain** (leaf + intermediates, in presentation order)
to disk as a **PEM bundle** of concatenated `-----BEGIN CERTIFICATE-----` blocks. The save runs
regardless of the verification verdict and is independent of linting (linting still proceeds
normally). It is only valid with `--from-host`, it **refuses to overwrite** an existing file
unless `--force` is given, and the parent directory must already exist. A
`saved presented chain to <path>` confirmation line is printed to **stderr** so it never pollutes
stdout. The saved bundle is **re-lintable** later via the normal `<PATH>` input — combine with
`--chain` to lint every certificate in it:

```sh
$ cargo run -p cli --features fetch -- --from-host example.com --save chain.pem
saved presented chain to chain.pem          # (stderr)
presented chain:
  ...
verification: valid
...

# Re-lint the saved bundle later, leaf-only or every cert:
$ mini-x509-lint chain.pem
$ mini-x509-lint --chain chain.pem

# Overwrite an existing file:
$ cargo run -p cli --features fetch -- --from-host example.com --save chain.pem --force
```

## Scope & limitations

This is a deliberately small linter; be aware of the boundaries:

- **Chain-aware lints are scoped to the `chain` source.** Each certificate is still linted
  independently by the per-cert sources, but with `--chain` (or over a `--from-host` presented
  chain) the `chain` source additionally runs cross-cert checks: issuer↔subject linkage, AKI↔SKI
  matching, issuer-is-CA, pathLen, validity nesting, and — with the `verify` feature (on by default
  in the CLI) — **signature verification** of each cert against its issuer's key (RSA/ECDSA/Ed25519
  via `ring`; ML-DSA/SLH-DSA via `fips204`/`fips205`). The chain is built order-independently, so a
  shuffled bundle is reordered (a `chain_not_in_order` Notice) rather than mis-reported. What's still
  out of scope: full **trust-anchor / path validation** against a root store (the `--from-host`
  `verification:` verdict is the only trust check, and it comes from `rustls`/`webpki`, not a lint),
  name-constraints propagation, and revocation.
- **The CA/Browser Forum lints are a focused subset.** The BR, EV, code-signing, and S/MIME
  sources implement a curated subset of each specification, not the full text.
- **PQC coverage is ML-DSA, SLH-DSA, and ML-KEM.** The `pqc` source covers the ML-DSA (FIPS 204)
  and SLH-DSA (FIPS 205) signature families and the ML-KEM (FIPS 203) key-encapsulation family.
  Composite PQC+classical schemes (`draft-ietf-lamps-pq-composite-*`) and stateful hash-based
  schemes (LMS/XMSS) are out of scope.
- **The `linter` crate never touches the network.** Live fetch (`--from-host` and friends) lives
  entirely in the standalone `fetch` crate behind the CLI's opt-in `fetch` feature; the lint
  engine itself stays network-free.
- **The `--purpose client` value is reserved** but not yet implemented (it currently behaves like
  `generic`).

## Development

```sh
cargo test                                   # run all tests
cargo clippy --all-targets -- -D warnings    # lint
cargo fmt --check                            # formatting
cargo audit                                  # dependency advisories
```

Test fixtures under `testdata/` are generated reproducibly with `openssl` (see
`testdata/generate.sh`). The linter is intentionally kept as an **independent oracle**, so
fixtures are never sourced from other certificate-generating tooling.

## Acknowledgements

The lint catalogue is inspired by [zlint](https://github.com/zmap/zlint) (Apache-2.0). All checks
are **reimplemented from scratch** against the underlying specifications (RFC 5280 and the
CA/Browser Forum Baseline Requirements, EV, Code Signing, and S/MIME profiles) — **no zlint code is
used**; only the idea of *which* rules are worth checking, and a naming sensibility, are borrowed.
