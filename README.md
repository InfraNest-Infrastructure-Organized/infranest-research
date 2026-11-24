<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/InfraNest-Infrastructure-Organized/infranest-research/main/.github/assets/infranest-logo-dark.svg">
    <img alt="InfraNest" src="https://raw.githubusercontent.com/InfraNest-Infrastructure-Organized/infranest-research/main/.github/assets/infranest-logo-light.svg" width="300">
  </picture>
</p>

<h1 align="center">InfraNest Research</h1>

<p align="center">
  <strong>Open measurements of email, DNS and HTTPS security on the world's most-visited websites.</strong><br>
  Pre-registered method, open code, aggregated data. Never per domain.
</p>

<p align="center">
  <img alt="Edition: 2026" src="https://img.shields.io/badge/edition-2026-0f172a">
  <a href="https://doi.org/10.17605/OSF.IO/P6YTU"><img alt="Pre-registered: OSF P6YTU" src="https://img.shields.io/badge/pre--registered-OSF%20P6YTU-14b8a6"></a>
  <img alt="Population: Chrome UX Report" src="https://img.shields.io/badge/population-CrUX%20Oct%202026-3b82f6">
  <img alt="Code licence: Apache-2.0" src="https://img.shields.io/badge/code-Apache--2.0-3b82f6">
  <img alt="Data licence: CC BY 4.0" src="https://img.shields.io/badge/data-CC%20BY%204.0-14b8a6">
  <img alt="Node.js 22" src="https://img.shields.io/badge/node-22-64748b?logo=nodedotjs&logoColor=white">
</p>

---

This repository holds the scanner, the analysers and the input lists behind the studies of
**InfraNest Research**: how well the most-visited websites stop others from sending email in their name,
sign their DNS, and serve HTTPS. Everything needed to repeat a scan is here; per-domain results are not, by design.

## Studies

| | Study | Population | Status |
|---|---|---|---|
| 1 | **Email security of the world's 100,000 most-visited websites** | 80,312 domains behind CrUX's global top 100,000 websites | **Published 24 Nov 2026** · [report and data](https://infranest.io/research/email-security-2026/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research) · [doi:10.5281/zenodo.24417472](https://doi.org/10.5281/zenodo.24417472) |
| 2 | **Email and DNS security of the most-visited Dutch, German and French websites** | .nl / .de / .fr domains in each country's CrUX top 50,000 (20,314 / 19,400 / 12,595) | Final scan 30 Nov · publishing 8 Dec 2026 |
| 3 | **Ready for 100-day certificates?** | to be registered | Publishing 16 Feb 2027 |

> [!IMPORTANT]
> **Pre-registered:** the protocol for edition 2026 (studies 1 and 2) is registered on OSF Registries:
> **[doi:10.17605/OSF.IO/P6YTU](https://doi.org/10.17605/OSF.IO/P6YTU)**. The registered text is in
> [`docs/protocol-1.0.pdf`](docs/protocol-1.0.pdf) (SHA-256 `ddc3039f…4fd20`), with a Markdown copy in
> [`docs/protocol-1.0.md`](docs/protocol-1.0.md).

Each study gets a page on [infranest.io](https://infranest.io/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research) and a DOI on
[Zenodo](https://zenodo.org/communities/infranest-research). Links are added here as they go live.

## What we measure

| Area | Measures | Standards |
|---|---|---|
| **Email** | Mail domains (MX, null MX), SPF validity and lookup count, DMARC record and the **effective** policy receivers are asked to apply | RFC 7208, RFC 9989, RFC 7505 |
| **DNSSEC** | Signed at the registry, zone validates, broken (confirmed by two resolvers and two scans) | RFC 4033–4035, RFC 8914 |
| **HTTPS** | Trusted certificate, expiry, lifetime (for the 100-day limit of March 2027), issuer | RFC 5280, CA/B Forum SC-081 |
| **Providers** | Who runs mail, DNS and web hosting, grouped by headquarters region | — |

The exact definitions, research questions and analysis plan are in the pre-registered plan.

## How we work

> [!NOTE]
> **Pre-registered.** Each study's questions, definitions and analysis are registered on OSF before any result
> is computed ([edition 2026](https://doi.org/10.17605/OSF.IO/P6YTU)). Every deviation is listed in the published method.

- **Defined populations.** The most-visited websites according to the [Chrome UX Report](https://developer.chrome.com/docs/crux)
  (CrUX), via [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists). Each list is frozen with the
  SHA-256 of its source file and of the Public Suffix List used (see `lists/*.meta.json`).
- **Checked.** A hand check of 100 domains against independent tools (checkdmarc, delv, openssl), an
  independent recount of every published number, and a test-retest sample.
- **Same analysers as the free tools.** SPF and DMARC are judged by the code behind InfraNest's
  [SPF checker](https://infranest.io/tools/spf-check/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research) and [DMARC checker](https://infranest.io/tools/dmarc-check/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research),
  so anyone can check one domain by hand and get the same verdict.
- **Polite.** DNS only through public validating resolvers; one TLS handshake per site, like a single visitor;
  at most two connections at once per /24 network; a shuffled order.
- **Totals only.** Results are published by country, popularity tier and sector — never per domain.

## Repository layout

```
scripts/research/
  build-crux-list.mjs        CrUX origins → registrable domains (Public Suffix List), best bucket per domain
  scan-cc-security.mjs       the scanner: SPF, DMARC, DNSSEC, HTTPS, providers
  _https-check.mjs           one TLS handshake per site
  recheck-https.mjs          re-checks network failures from a second location
  summarise-cc-security.mjs  totals per tier with 95% Wilson intervals
  providers.mjs              provider recognition and headquarters regions
functions/api/
  _spf.js, _dmarc.js         SPF and DMARC analysers (shared with the free tools)
docs/
  protocol-1.0.md / .pdf     the registered protocol (edition 2026)
  research/                  per study: implementation notes (deviations, fixes, decisions) and review log
lists/
  crux-*-202610.csv          the frozen input lists: "bucket,domain"
  crux-*-202610.csv.meta.json  provenance: source URL, SHA-256, counts per bucket
```

The layout mirrors the internal repository, so the scanner commit recorded in each run (`run.json`) maps to
a tag here, and the files are byte-identical.

## Repeat a scan

Requires **Node.js 22**. No dependencies to install.

```sh
# 1. Build a list from a CrUX release (or use the frozen one in lists/)
node scripts/research/build-crux-list.mjs --crux global-202610.csv.gz --psl public_suffix_list.dat \
  --max-bucket 100000 --month 202610 --out research/lists/crux-global100k-202610.csv

# 2. Scan (resumable: run it again to retry read errors and confirm broken DNSSEC)
node scripts/research/scan-cc-security.mjs --list lists/crux-global100k-202610.csv --list-source crux \
  --list-id crux-202610 --tld all --top 1000000 --out research/global --vantage "your location"

# 3. Re-check HTTPS network failures from a second location
node scripts/research/recheck-https.mjs research/global --vantage home

# 4. Totals
node scripts/research/summarise-cc-security.mjs research/global
```

Per-domain output stays in `research/`, which is ignored by git. Please keep it that way: results for single
domains can identify their owners.

## Site owners

Want to know what was measured, or be left out of future editions? See
**[how our scanner works](https://infranest.io/research/scanner/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research)** or write to
**[research@infranest.io](mailto:research@infranest.io)**. Opted-out domains are skipped and only counted, never named.

## Cite

Use **Cite this repository** on GitHub (from [`CITATION.cff`](CITATION.cff)), or cite the study itself:

> Steenman, J. (2026). *Email security of the world's 100,000 most-visited websites* (Version 1.0) [Research report].
> InfraNest Research. https://doi.org/10.5281/zenodo.24417472

## Licence

- **Code** (`scripts/`, `functions/`): [Apache-2.0](LICENSE).
- **Input lists and documentation** (`lists/`, `docs/`): [CC BY 4.0](LICENSE-DATA.md). The lists are derived from
  the Chrome UX Report (Google, CC BY 4.0).

<p align="center"><sub>InfraNest Research is part of <a href="https://infranest.io/?utm_source=github&utm_medium=readme&utm_campaign=infranest-research">InfraNest</a> — one place for your servers, monitoring, DNS, domains and certificates.</sub></p>
