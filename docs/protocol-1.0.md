# Email and DNS security of the most-visited websites, worldwide and in the Netherlands, Germany and France: pre-registration protocol

**InfraNest Research · Edition 1 (2026) · Pre-registration protocol, version 1.0 · 13 November 2026**  
Code, scanner and input lists: [github.com/InfraNest-Infrastructure-Organized/infranest-research](https://github.com/InfraNest-Infrastructure-Organized/infranest-research) (scanner `scripts/research/scan-cc-security.mjs`; study 1 ran files byte-identical to public commit 7339042, tag `scanner-e0c9063`)  
Contact: research@infranest.io · Licence of this document: CC BY 4.0

This protocol fixes the research questions, population, definitions, quality checks and the comparisons we
will publish before any result is computed, so the results cannot steer what we choose to report. For study 1,
data collection began on 13 November 2026 at 19:22 UTC, shortly before registration, with scanner code that
implements draft 0.9 of this protocol; no result had been computed or viewed (section 7.2). For study 2 all analysis decisions are fixed here, before its final scans; what was seen of the data
before registration is listed in section 7.4. Changes after registration are allowed under the deviations
policy in section 7.2.

---

## 0. Publications in this edition

| # | Study | Population | Languages | Planned publication |
|---|---|---|---|---|
| 1 | Email security of the world's 100,000 most-visited websites | CrUX global top 100,000 origins (80,312 domains) | English | November 2026 |
| 2 | Email and DNS security of the most-visited Dutch, German and French websites | .nl / .de / .fr domains in CrUX's per-country top 50,000 origins (20,314 / 19,400 / 12,595) | English (authoritative) + NL/DE/FR country summaries | December 2026 |

Study 1 follows InfraNest's September 2026 measurement of SPF and DMARC on the Tranco top 10,000, now measured
with this protocol's code and definitions,
and is the first study in this edition.
Its headline is the whole top 100,000; the CrUX rank bands inside it (1–1,000 up to
50,001–100,000) show how security changes with popularity across two orders of magnitude. Study 1 is email-first:
DNSSEC, HTTPS and providers are measured in the same scan and published in its data files, but the text
leaves them to study 2 and the certificate study.
Study 2 uses study 1 as its global comparison (RQ6), band by band. A separate study on certificate lifetimes
("Ready for 100-day certificates?") follows in February 2027, before the 100-day limit of 15 March 2027, with
its own registration.

## 1. Purpose

Measure how well the most-visited websites, worldwide (study 1) and in the Netherlands, Germany and France
(study 2), protect their domain
against email spoofing, sign their DNS, and serve HTTPS. Publish the totals, the method and the data
openly, so journalists, researchers and site owners can check and reuse them.

The study is descriptive. It says how things are set up, not why, and it never names individual sites.

## 2. Research questions

| | Question | Primary measure |
|---|---|---|
| RQ1 | How many of the most-visited sites per country stop others from sending email in their name? | Mail domains with enforced DMARC (section 5) |
| RQ2 | How many have an SPF record that works, and how many are close to breaking it? | Valid SPF; SPF at 8–10 of 10 lookups |
| RQ3 | How many sign their DNS with DNSSEC, and how many signatures fail? | DS at registry; validates; broken |
| RQ4 | How many serve a trusted HTTPS certificate, and how many still use certificates valid for more than 100 days, which can no longer be issued from 15 March 2027? | Trusted; expired; lifetime > 100 days |
| RQ5 | How do the three countries differ, and does popularity or sector make a difference? | RQ1–4 by country × band and country × sector |
| RQ6 | How do the country results compare with the world's most-visited websites? | RQ1–4 against the global top 100,000 (study 1, measured with the same code and definitions and re-scanned in study 2's final window), compared **band by band**: a country's band against the global band of the same rank, never a whole country list against the whole global list. The September 2026 post (Tranco top 10,000, older analyser) is bridged through a re-scan of that same Tranco list with this plan's code (section 4), not compared directly |

### Expectations, stated before any result was computed

Written down so we can report honestly whether they held. "Under the section 8 rule" means the decision rule for
differences in section 8. These three are the only confirmatory comparisons besides the primary outcomes.

- **E1 (study 2):** the DNSSEC-signed share in the .nl list exceeds the .de list by at least 10 percentage points
  (point estimate), with a 95% Newcombe interval for the difference that excludes zero. Reason: SIDN's incentive programme drove signing by large registrars
  ([SIDN 2020](https://www.sidn.nl/en/news-and-blogs/dnssec-adoption-heavily-dependent-on-incentives-and-active-promotion);
  Chung et al., IMC 2017, on the role of registrars).
- **E2 (study 1 and each country in study 2):** the share of mail domains with enforced DMARC is higher in band
  1–1,000 than in all lower bands pooled, under the section 8 rule; where band 1–1,000 has fewer than 100 mail
  domains, E2 is reported as "not testable" for that list.
- **E3 (study 2):** for each country, the share of valid SPF records at 8–10 lookups is higher than in the global
  band of the same rank, under the section 8 rule, in a majority of that country's bands with n ≥ 100; E3 is
  reported per country. (Basis: the 11 November Tranco pilot of the .nl top 1,000 showed 22.9% against 14.3% in the
  September 2026 global top 10,000, both as a share of SPF-publishing mail domains under the September definition.)

## 3. Prior work and what this study adds

| Source | Type | What it found / measures | Relevance |
|---|---|---|---|
| Tatang, Zettl, Holz: *The Evolution of DNS-based Email Authentication: Measuring Adoption and Finding Flaws*, RAID 2021 ([CASA](https://casa.rub.de/en/research/publications/detail/the-evolution-of-dns-based-email-authentication-measuring-adoption-and-finding-flaws)) | Peer-reviewed | Longitudinal SPF/DMARC/DKIM adoption; DMARC grew about tenfold in five years but was still low overall | Method precedent; context for the trend |
| Hu & Wang: *End-to-End Measurements of Email Spoofing Attacks*, USENIX Security 2018 ([USENIX](https://usenix.org/conference/usenixsecurity18/presentation/hu)) | Peer-reviewed | Tested 35 email providers: most had the protocols needed to detect spoofing, yet still let forged mail reach the inbox | Why enforcement (not just a record) matters |
| Chung et al.: *A Longitudinal, End-to-End View of the DNSSEC Ecosystem*, USENIX Security 2017 ([USENIX](https://usenix.org/node/203653)) | Peer-reviewed | 31% of DNSSEC-enabled .com/.org/.net domains fail to publish all records needed for validation; growth is driven by a few DNS operators | DNSSEC context; why "signed" ≠ "valid" |
| Chung et al.: *Understanding the Role of Registrars in DNSSEC Deployment*, IMC 2017 (doi:10.1145/3131365.3131373) | Peer-reviewed | Registrars largely determine whether their customers' domains are signed | Basis for E1 |
| Le Pochat et al.: *Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation*, NDSS 2019 ([tranco-list.eu](https://tranco-list.eu)) | Peer-reviewed | The ranking the pilot and September sampled from | Population source of the pilot and September; replaced by CrUX (section 4) |
| Ruth, Kumar, Wang, Valenta, Durumeric: *Toppling Top Lists: Evaluating the Accuracy of Popular Website Lists*, IMC 2022 ([PDF](https://zakird.com/papers/toplists.pdf)) | Peer-reviewed | Of the lists evaluated, CrUX matched Cloudflare's traffic data best (2022) | Why the populations come from CrUX (section 4) |
| Ruth, Fass, Azose, Pearson, Thomas, Sadowski, Durumeric: *A World Wide View of Browsing the World Wide Web*, IMC 2022 ([PDF](https://zakird.com/papers/browsing.pdf)) | Peer-reviewed (Stanford, Google) | Chrome telemetry of several hundred million users: browsing is highly concentrated (six sites take 25% of page loads), and most websites are country-specific — of sites in any country's top 1,000, over half are not in any other country's top 10,000 | Why study 2 uses per-country populations rather than one global list |
| SIDN Labs open data ([stats.sidnlabs.nl](https://stats.sidnlabs.nl/en/dnssec.html), CC BY 4.0) | Registry | 59.5% of .nl signed (3,711,976 of 6,243,816) on 10 Nov 2026; ≈0.11% of .nl domains bogus (Jun 2026) | Zone-wide comparison for RQ3 (re-fetch on the scan date) |
| DENIC monthly DNSSEC statistics ([denic.de](https://www.denic.de/en/products/statistics-about-de/monthly-domain-statistics-of-de/)) | Registry | 455,778 signed .de domains on 31 Oct 2026; 2.5% of 18,371,249 .de domains (DENIC total, 31 Oct 2026) | Zone-wide comparison for RQ3 |
| AFNIC, *The .FR in 2025* ([afnic.fr](https://www.afnic.fr/wp-media/uploads/2026/03/The-FR-in-2025.pdf)) | Registry | 21.6% of .fr signed (932,000 names) in 2025 | Zone-wide comparison for RQ3 |
| CBS: *Toepassing van internetstandaarden voor websites van bedrijven, 2023* ([cbs.nl](https://www.cbs.nl/nl-nl/longread/aanvullende-statistische-diensten/2024/toepassing-van-internetstandaarden-voor-websites-van-bedrijven-2023?onepage=true)) | Official statistics | Dutch business websites and internet standards | NL context, different population |
| Forum Standaardisatie / Internet.nl government measurements (via [SIDN](https://www.sidn.nl/en/news-and-blogs/less-prominent-government-domains-have-worse-security)) | Government | Less prominent government domains lag on mandatory standards | Sector context for government |
| EasyDMARC 2026 report ([easydmarc.com](https://easydmarc.com/blog/ebook/dmarc-adoption-report-2026/)), Red Sift, PowerDMARC country reports | Industry, not peer-reviewed | E.g. 1.8M domains: 52.1% valid DMARC, 22.9% enforcing | Not cited in study 1 (see rule below) |
| InfraNest: SPF and DMARC across the top 10,000 domains, Sept 2026 (infranest.io/research/email-auth-2026-09.json) | Own | Global baseline (Tranco top 10,000, older analyser; cross-checked with checkdmarc) | Bridged through a re-scan of the same list with this plan's code (section 4) |

**Industry and consultancy reports** (vendors, consultancies such as Deloitte, PwC or KPMG, security firms):
grey literature. They are cited only when (a) they publish their population, date and definitions, and (b) the
text needs them for context, never for a like-for-like comparison of numbers, and always labelled
"industry report, not peer-reviewed". Survey-based reports (what organisations say they do) are not compared
with measurements (what DNS shows). Official grey literature (NIST, ENISA, national statistics offices,
registries, government standardisation bodies) is preferred over commercial reports. Study 1 cites none.

**What is new here:** one method applied to three countries at once; the most-visited sites rather than whole
zones, from CrUX, the list that matched real traffic best in an independent 2022 evaluation, with the popularity gradient from the top 1,000 to the
top 100,000; email, DNSSEC and HTTPS together; the 100-day certificate angle; a pre-registered plan; and open
method and data. We do not
claim to be the first to measure any single item.

## 4. Population

- **Source: the Chrome UX Report (CrUX)** — Google's public popularity data, as monthly buckets of the
  origins Chrome users load most (top 1,000, 5,000, 10,000, 50,000, …), per country and globally. We use the
  per-country and global files published by [zakird/crux-top-lists](https://github.com/zakird/crux-top-lists)
  (built from the CrUX BigQuery data), release **October 2026**. CrUX matched real traffic best of the lists evaluated in
  an independent evaluation ([Ruth et al., "Toppling Top Lists", IMC 2022](https://zakird.com/papers/toplists.pdf)).
- **Why not Tranco (as in the pilot and September):** in the November dry run, the Tranco .nl list was
  dominated from rank ~3,000 to 10,000 by a network of generated domains (46–71% per 1,000-rank band: on
  Cloudflare, no mail, random 13–22-letter names). Of the 4,110 such domains, 6 appear in CrUX's Netherlands
  list. Tranco's .de, .fr and global lists were barely affected (≤ 2%), but one source for all populations
  keeps the comparison fair. Not a criticism of Tranco: it combines several providers' rankings (DNS, links, traffic), which such
  networks can generate.
- **Tranco's role now: robustness check, not a population.** The two lists overlap too little to combine
  (share of Tranco 947N2's top 10,000 also in the matching CrUX list — global: against CrUX's global top
  10,000; countries: Tranco's top 10,000 domains of that ccTLD against the CrUX country list: global 40%,
  .nl 34%, .de 54%, .fr 60%), and their overlap leans towards the very largest sites. So Tranco is used twice, never for a
  headline: (1) the headline measures are recomputed on the domains present in both lists (section 8, check 1) and the method says
  whether they stay within the confidence intervals; (2) the September 2026 population itself, Tranco list
  **K9PXW**, top 10,000 (checked identical to September's 10,000 domains), re-scanned with this plan's code,
  bridges September to now: "same list, new analyser" and "new list, new analyser" side by side. Check (1)
  uses Tranco 947N2 (November 2026) and needs no scan of its own. Both lists stay archived
  (not public; both are retrievable from tranco-list.eu by their IDs).
- **From origins to domains:** each origin (https://jouw.postnl.nl) becomes its registrable domain
  (postnl.nl) with the Public Suffix List (ICANN and private sections; version recorded by SHA-256); a domain
  takes the best bucket of any of its origins. `scripts/research/build-crux-list.mjs` does this and records
  the provenance of every list. Checked on the October 2026 lists: entries under a private-section suffix
  (`*.vercel.app`, `*.service.gov.uk`, …) are 0.2% of the global top 10,000 (1.0% at 1,000,000) and at most
  33 domains per country list, so the choice of PSL section does not move any result; it is stated, not changed.
- **Study 1 (global):** the registrable domains behind the 100,000 origins Chrome users worldwide load most
  (80,312 domains in the October 2026 release: 816 / 3,370 / 4,183 / 32,310 / 39,633 in the 1k / 5k / 10k /
  50k / 100k buckets). Why 100,000 and not 10,000: the 8,369 domains of the top 10,000 already give about ±1–1.3 points, but only
  describes the very top; the wider list shows whether security falls off with popularity, for about two
  extra hours of scanning. Why not 1,000,000 (763,843 domains): about 15 million DNS queries would need our
  own validating resolver rather than two public ones; planned for edition 2.
- **Study 2 (per country):** the .nl / .de / .fr domains among the 50,000 origins Chrome users in the
  Netherlands / Germany / France load most (October 2026: 20,314 / 19,400 / 12,595 domains).
- **Bands (the tiers used for comparisons):** disjoint bands of origin rank — 1–1,000; 1,001–5,000; 5,001–10,000;
  10,001–50,000; and (global only) 50,001–100,000. A domain's band is the best band of any of its origins.
  Cumulative figures (top 1,000 / 5,000 / 10,000 / 50,000 / 100,000) are reported alongside, but comparisons
  (RQ5, RQ6, E2, E3) always use bands. CrUX gives no rank within a band, so domains in one band are equal (lists
  are ordered alphabetically within a band, only to be deterministic). Domain counts per bucket in this section
  are per band.
- **One organisation, many domains:** 7.7% of the global top 10,000 are name variants of a domain already in
  the list (flashscore.* 25 times, amazon.* 23, vinted.* 13, google.* 12, zalando.* 11). Such domains usually
  share one setup, so they are not independent observations. The headline counts per domain (as the
  literature and September do); a sensitivity check counts each organisation once (section 8). The country
  lists, with one TLD each, are hardly affected.
- **Release:** the October 2026 release is the latest available on every scan date in this edition (the
  November release appears around 8 December); all lists are frozen by SHA-256 in their `.meta.json`.
- **Sectors:** from Wikidata (official website P856, with instance-of P31 and industry P452), mapped to
  government, finance, education, retail, news and media, and other. Coverage will be partial.
  Unmatched domains are "unclassified", and coverage per country is reported.
- **Exclusions, per measure:** a domain is unreadable for a measure only when both resolvers fail on it
  (a single resolver's failure always gets a second opinion). A read error on the MX or `_dmarc` record removes
  the domain from all email measures (DMARC, SPF, fully configured); an unreadable SPF record or SPF include removes it
  from the SPF measures and "fully configured" only; neither affects DNSSEC or HTTPS. Unreadable counts are published per measure. Domains with no MX, a null MX
  (RFC 7505) or an unusable MX are left out of the email measures only, as in September. Domains whose owner asked to be
  left out are skipped and only counted.

**Known limits:** a ccTLD is not a country: much-visited Dutch sites on .com (bol.com, booking.com) are
outside the .nl population by definition. CrUX counts Chrome users who share usage statistics, not all
visitors; it matched real traffic best in that evaluation. A bucket's domains cannot be ranked against each other.

## 5. Measurements and definitions

DMARC as published is defined as in the September 2026 study; "SPF valid" and the effective DMARC policy are
stricter (see their rows). September is therefore compared only through the Tranco re-scan (section 4).

| Measure | Counts as yes when | Standard |
|---|---|---|
| Mail domain | A real MX record: not a null MX, and not MX hosts that point nowhere a sender can reach (`localhost`, single-label names), which are counted as "unusable MX" | RFC 7505 |
| SPF published | A `v=spf1` TXT record | RFC 7208 |
| SPF valid | Exactly one record and no permanent error in the records it reaches: at most 10 DNS lookups, at most 2 void lookups (an `a` name without any IPv4 or IPv6 address, an `mx` name without MX, an include target without TXT), no include loop, no missing include, no unknown term, typo, bad IP, empty value or invalid characters. Errors inside an included or redirect target (two SPF records, a bad address, an empty term, invalid characters) count as "included record invalid". A macro term (`%{…}`) costs its lookup and is not judged. An include that cannot be read makes SPF unreadable for that domain (retried), never "valid". Stricter than September's rule (see the start of this section; September is bridged in section 4) | RFC 7208 §4.5, §4.6.4, §5.2 |
| SPF near the limit | Valid with 8–10 lookups, as a share of valid SPF records | (our threshold) |
| DMARC published | Exactly one `v=DMARC1` record at `_dmarc.<domain>`. Two records are discarded by receivers and counted as "multiple records" (not published) | RFC 9989 (May 2026; obsoletes RFC 7489) |
| DMARC enforced | The **effective policy** (what receivers are asked to apply) is `quarantine` or `reject`. Every mail domain falls in exactly one bucket, assigned in this order: **missing** (no record, or two records); **invalid** (a record strict receivers may not parse: invalid characters, a missing `;`, no or an invalid `p=`); **partial** (`pct` 1–99 with `p=quarantine`, with or without `t=y`: not enforced); `pct` 1–99 with `p=reject` counts as effective **quarantine** (enforced), or **none** when `t=y`, because RFC 7489 §6.6.4 has receivers apply the next lower policy to messages not sampled and RFC 9989 removes `pct`; otherwise `p=`, lowered by exactly one level when `t=y` (RFC 9989 §4.7) and/or a legacy `pct=0` (RFC 9989 Appendix A.6), giving **none / quarantine / reject**. An invalid `sp=` is ignored: only `p=` is judged, because subdomains are out of scope (RFC 7489 §6.6.3 would treat such a record as having no valid policy; the number of records with an invalid `sp=` is reported). An invalid `pct` value is ignored, as receivers do (RFC 7489 §6.3; RFC 9989 drops `pct`). Records with `pct` below 100 are also counted apart. The six shares and their counts are published (shares are rounded one by one, so use the counts for sums). The policy as published (`p=`, of domains with one record) is reported apart, for comparison with September | RFC 9989, RFC 7489 |
| **Not protected against spoofing** (headline RQ1) | Mail domain whose effective DMARC policy is not quarantine or reject (missing, invalid, partial or none). **Primary outcome** (section 8) | — |
| Fully configured | Valid SPF and enforced DMARC, as a share of mail domains with readable SPF and DMARC (not the complement of "not protected") | — |
| SPF over the limit | A published SPF record needing more than 10 lookups, as a share of mail domains publishing a readable SPF record | RFC 7208 §4.6.4 |
| DNSSEC signed | A DS record for the domain at the registry; population: domains whose DS lookup could be read (a signed domain with an unreadable zone still counts as signed) | RFC 4033–4035 |
| DNSSEC zone validates | Signed, and the validating resolver (Cloudflare; Google when Cloudflare cannot answer) sets the AD flag on the SOA answer; includes zones where only one record set is broken. Every signed domain is in exactly one state: valid / broken, whole zone / broken, partly / broken, unconfirmed / insecure (DS present, no AD flag, not broken by the rule below) / unreadable. "Zone validates" = valid + broken, partly. Shares are published over signed domains with a readable state, and also over all domains with a readable DNSSEC state | RFC 4035 |
| DNSSEC broken | Whole zone: BOTH resolvers answer SERVFAIL for the SOA, EACH with a DNSSEC reason (RFC 8914 extended error 1, 2, 5–12 or 25, or "DNSSEC validation failure"), and the same query with checking disabled (`cd=1`) answers. Partly: the domain is signed and its zone validates, but the A record of the bare domain or a record the email checks need (MX, SPF, `_dmarc`) fails that same test in the domain's own zone; every failed name is checked and the domain's own zone takes precedence. A failure reached through a CNAME into someone else's zone, or on a domain that is not signed itself, is counted apart ("broken elsewhere": for email and SPF; for the website address only when the A record of the bare domain of a signed, validating zone follows a CNAME into another zone) and never as this domain's DNSSEC. Broken is published only when two scans saw the same state on the same record set; unconfirmed cases are counted apart. Domains that no longer exist (NXDOMAIN at the registry) are removed and counted | RFC 4035, RFC 8914 |
| HTTPS answers | A TLS handshake completes on port 443. The bare name is tried first; if it gives no handshake or an untrusted certificate, `www.` is tried, and the domain's result is the `www.` result when that is trusted (or when only `www.` answers), else the bare name's result. One address per name (the first IPv4 address, else the first IPv6 address) to the address found over DNS-over-HTTPS (never the scanning machine's resolver). Population: domains whose site name resolves to a public address. Not resolvable (neither name has a public address and at least one had a read error, including broken DNSSEC; retried once) and "no public address" (none, or only private/loopback/documentation addresses, which are never contacted) are counted apart. A network failure from the scan server is re-checked from a second location. Reasons for no answer are those of the name actually tried | — |
| HTTPS trusted | Chain validates against the Mozilla-derived root store bundled with the recorded Node.js version, and the name matches. Node does not fetch missing intermediate certificates (browsers may), so a chain missing an intermediate counts as untrusted; this is a stated limitation. Denominator: domains that completed a handshake from the scan server or the second location (for those answering only from the second location, the certificate seen there counts) | RFC 5280, RFC 9525 (obsoletes RFC 6125) |
| Certificate expired / expiring | Expired = the end date has passed (whatever error a client reports first); expiring = a trusted certificate with 0–7 days left (not 30: ACME clients renew around 30 days before expiry); both as a share of all answering sites | — |
| Certificate lifetime | notAfter − notBefore of **trusted** certificates, in buckets ≤ 100, 101–200 and > 200 days | CA/B Forum SC-081v3: max 200 days from 15 Mar 2026, 100 from 15 Mar 2027, 47 from 15 Mar 2029 ([summary](https://support.dnsimple.com/articles/announcement-ssl-certificate-validity-changes/)) |
| Issuer | Organisation (else common name) in the leaf certificate's issuer | — |

**Organisational domain:** RFC 9989 replaces the Public Suffix List with a DNS tree walk. This does not
affect us, because we only query each registrable domain itself. Domains without their own record count as
missing even if a policy exists higher up the tree; such inherited policies are not considered.

**Collected for provider measures and later studies** (same scan, public DNS only):
- **Providers per role:** mail (MX hosts), sending services (SPF includes), DNS hosting (NS hosts), web network (the
  network operators of up to four of the site's IPv4 addresses, looked up without a location hint so a CDN answers
  with its own network rather than a cache inside an internet provider, and named by Team Cymru's IP-to-ASN
  service, most specific prefix), DMARC report service (`rua` domains) and certificate issuer. A value under the
  domain itself (mx.example.nl for example.nl) counts as "own domain". Headquarters means the company that
  operates the service, not its parent group. CDNs and proxies are labelled as such. Matched to companies in `scripts/research/providers.mjs`, each with the
  country of its headquarters, giving shares per provider and per region (US / EU / rest of Europe / other).
  Unmatched values are listed in full in an internal file and the table extended after the dry run. Published
  per role: the share of domains for which no value matched a provider or the domain itself ("unrecognised").
  Denominators: mail = mail domains; sending = mail domains with a readable SPF record; DNS = domains with
  readable NS; web = domains whose site network was measured; report services = mail domains with a readable
  DMARC record that names a `rua`; issuer = sites with a trusted certificate; US dependency = mail domains.
- **Dependency:** the share of mail domains that use a US-based provider for at least one of mail, DNS or web
  network. This is a lower bound, because unrecognised providers count as non-US. "Behind Cloudflare"
  (a proxy or CDN) is reported as such, not as hosting.
- **Other measures:** IPv6 on the website and the first mail host, CAA, MTA-STS and TLS-RPT (record present).

**Planned for study 2** (to be built and verified before the study 2 CrUX dry run and fixed in version 1.1; study 1 is
frozen without them):

| Measure | Counts as yes when | Standard |
|---|---|---|
| DANE for mail | A TLSA record at `_25._tcp.<mx host>` for the domain's MX hosts, validated by DNSSEC (the MX host's zone signed and validating); reported per mail domain as all / some / none of its MX hosts | RFC 7672, RFC 6698 |
| MTA-STS policy | A `_mta-sts` TXT record **and** a policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt` that parses, with `mode` testing / enforce / none, and whose `mx` patterns cover the published MX hosts. One HTTPS request per domain that publishes the record | RFC 8461 |

Both are DNS or a single HTTPS fetch, so they fit the ethics rules in section 9.
- **In study 2:** a short "who runs the email of the top sites" section and the dependency figure. The full
  provider study (and its trend over editions) follows separately.

**Not measured:** DKIM (selectors cannot be listed from DNS), whether real mail passes DMARC alignment,
STARTTLS on the mail servers (DigitalOcean blocks outbound port 25, and connecting to mail servers is outside
the ethics rules), subdomains, HTTP redirects and HSTS (would need an HTTP request; HSTS goes into the
certificate study), and registrar per domain (registry terms forbid bulk lookups; section 12). Each is
named in the published method as "not measured".

## 6. Data collection

- **Tool:** `scan-cc-security.mjs`, reusing the analysers behind InfraNest's free SPF and DMARC tools; the
  scanner additionally counts void lookups from `a`/`mx` terms, and the effective DMARC policy is computed in
  the summariser. The git commit is recorded with the data.
- **DNS:** Cloudflare DNS over HTTPS, with Google as fallback (both validating resolvers). Answers are cached
  for the run (failures and timeouts never are), concurrency is modest, and in study 1 no queries go to the sites' own servers except through the
  resolvers. From study 2, our own recursive resolver queries authoritative name servers directly, as any
  resolver does.
  **From study 2 on:** our own validating resolver (Unbound on the scan server, default trust anchor, no
  forwarding) gives a third opinion wherever the two public resolvers disagree or fail, and on every
  "broken DNSSEC" candidate. It removes the dependence on how two public caches behave and is the base for a
  1,000,000-domain scan in edition 2. Study 1 runs as verified (two public resolvers), and says so.
- **HTTPS:** one TLS handshake per name, no HTTP request; 8 seconds without activity or 10 seconds in total ends it. Run from a single vantage
  point: a DigitalOcean server in Frankfurt (FRA1), `scanner.research.infranest.io`, whose reverse DNS points to
  a public page explaining the scanner.
- **Window (study 2):** all three countries and the global top 100,000 scanned within the same 72 hours. **Retry (both studies):** unreadable domains are retried once
  24 hours later by re-running the same command: only domains with a read error, or with broken DNSSEC
  not yet seen twice, are scanned again, and their new result replaces the old one.
- **Politeness:** shuffled order (seed recorded), at most 2 handshakes at once per IPv4 /24, in study 1 DNS only
  through the two public resolvers.
- **Second vantage point:** domains that give the scan server no handshake are re-checked from a second
  location. Those that answer there are counted as "blocks the scan server", not as having no HTTPS.
  **From study 2 on** a second location outside the EU also
  re-reads every "broken DNSSEC" and "unreadable" domain, so geo-dependent DNS answers are caught and a broken
  zone is confirmed from two networks as well as two scans.
- **Recorded per run** (`run.json`): list file, source (CrUX or Tranco) and ID, seed, scanner commit, Node version, vantage point,
  and start and finish time of each run segment.
- **Reproducible:** the code runs on Node 22 with no third-party dependencies; the exact Node version (study 1:
  22.22.1, which also fixes the root store used for HTTPS) is recorded in run.json, so anyone can rerun a scan
  from the published input lists.
- **Memory:** the scanner runs with `node --max-old-space-size=760` on the 1 GB scan server (its per-run DNS
  cache grows with the list); without it the first study 1 segment stopped at 77,295 of 80,312 domains.
- **Study 1 run record:** main scan 13 Nov 2026, 19:22–21:40 UTC, scanner files byte-identical to public commit 7339042
  (development commit e0c9063, recorded in run.json), Node 22.22.1, two segments (the first
  stopped when Node ran out of memory; the same command, list and seed resumed it, as the resume logic is
  designed to do); 80,312 of 80,312 domains have a result; 303 queued for the retry pass. The resuming
  segment also re-scanned the ~306 domains the first segment had queued; for those, the two scans that confirm
  broken DNSSEC were about two hours apart. September bridge
  (K9PXW) 13 Nov, 35 queued for retry.
- **Frozen at registration** (SHA-256): `results.ndjson` is append-only, so later passes only add lines after the
  registered length; `run.json` is rewritten by each pass (earlier segments are kept), so its hash is that of the
  version at registration:
  - study 1 main scan `results.ndjson`: 74,073,273 bytes, `a8ed52a94564ab366c5e5fea6d21c924f5ec7139640632841b8ea266a04184de`;
    `run.json`: `71e995aa5231ebccd2f608c9605286d381fa48a52f26947ffb9ceb0f0743f07f`
  - September bridge (K9PXW) `results.ndjson`: 9,522,550 bytes, `d21ec4d7253f807c71e1f3a493c95386014a1096c0e28eb89ee59408147b3125`;
    `run.json`: `6ba3576a45f7aac73b7b96608114e39d5c7a7499571fdb276d7f656fb0838533`
  - scanner: public commit 7339042 (`scan-cc-security.mjs` SHA-256 `408748c9af580312…`), byte-identical to the
    development commit e0c9063 that ran the scan.
  The analysis code that computes the published numbers will implement exactly the rules in sections 5 and 8
  (it is not part of the frozen scanner files); it is published with the study, and any rule it applies that
  differs from this protocol is a deviation.
- **Schedule:** see section 11.

## 7. Quality assurance

### 7.1 Pilot (done, 11 November 2026)

Top 1,000 .nl from Tranco `947N2`; 4 unreadable. Three method fixes came out of it:

- DNSSEC is checked first, so broken zones are no longer filed as unreadable.
- HTTPS falls back to `www.` when the bare domain's certificate fails.
- "Expiring within 30 days" was replaced by "expired" and "expiring within 7 days", reported apart.

A hand check of 8 random domains matched independent lookups on all of them.

### 7.2 Before publishing

1. **Hand check:** 100 random readable domains (study 1: from the global list; study 2: stratified across the
   three countries):
   - SPF and DMARC against [checkdmarc](https://github.com/domainaware/checkdmarc), as in September;
   - DNSSEC against `delv`/`dig +dnssec` or DNSViz;
   - HTTPS against `openssl s_client`.

   Study 1: 100 domains drawn at random from the global list (seed recorded), plus up to 20 per rare state (DMARC
   invalid, SPF over the limit, DNSSEC broken, certificate expired). Disagreements caused by DNS changes between
   scan and check are counted apart. Target: at least 98% agreement per measure, and every disagreement explained
   in the method. If a measure falls below 98% because of a scanner error, the error is fixed and the measure
   recomputed (or the list re-scanned), recorded as a deviation; if that cannot be done before publication, the
   measure is not published.
2. **Independent recount:** a person, or a separate AI model run that has not seen our analysis code, recomputes every
   published number from the raw results with their own code. Any difference blocks publication until explained.
2a. **Test-retest (full second run):** the whole list is scanned a second time, 36–48 hours after the main
   scan, with the same code and list and a new seed. Agreement per measure is published (share identical, and
   Cohen's kappa for the categorical measures such as the effective DMARC policy). Low agreement (kappa below
   0.80 or below 95% identical) is shown next to every number of that measure; below kappa 0.60 the measure is
   left out of the text. The second run gets its own retry pass. An incomplete run is completed by the resume
   logic with the same code within 24 hours, otherwise the list is re-scanned and the incomplete run reported. The runs are **never combined**: the headline, including the confirmation of broken DNSSEC, comes from the
   main scan and its retry pass; the second run measures reliability and is sensitivity check 4 (section 8). A third run
   happens only to investigate a measure with low agreement.
2b. **Pre-registration:** this plan, frozen as version 1.0, is registered on OSF Registries (timestamped, read-only, with a DOI)
   before any study 1 number is computed (the summary runs after the deposit), and as 1.1 with the study 2
   additions before the study 2 scans. The published method cites the deposited version and lists every
   deviation from it, each with its date, reason, whether it was decided before or after any result for the
   affected measure was seen, and its effect; where feasible the registered analysis is reported alongside the
   changed one. Deviations are also filed as an update to the OSF registration. **Timing, stated openly:** data collection for study 1 began on 13 November 2026 at 19:22 UTC
   with scanner code that implements draft 0.9 of this protocol, which was being finalised at the time (committed
   19:25 UTC in InfraNest's private development repository; not public). Version 1.0 is registered after that,
   before any study 1 result was computed or viewed. The changes from 0.9 to 1.0 concern the second run, the
   bridge list (sensitivity check 3), sensitivity check 4, the rules for industry reports (section 3) and the text
   rules in 7.3; the measure definitions and the headline analysis are unchanged.
3. **Heads-up, not a review (optional):** about a week before publishing, a short note with the method
   and key numbers goes to SIDN Labs, Internet.nl and the registries ("publishing on [date]"). No reply is
   needed and publication never waits for one. Credibility comes from the open method, data and code,
   which let anyone check the numbers.
4. **Corrections:** the published page carries a version history and a "Found an error? Tell us" link.
   Corrections are dated and never silently overwritten.

### 7.3 The text and its review

- **Written after the numbers.** Population, method, ethics and limitations can be written in advance. Findings
  and their interpretation are written only after the summary; the only statements fixed before are the
  expectations in section 2, and the text reports whether each one held.
- **No number typed by hand.** Every number in the text, tables, charts, PDF, metadata and downloads is
  rendered from the study's data file or from one module of fixed list facts.
- **Sources:** peer-reviewed papers, RFCs and official datasets and statistics, each verified against its
  publisher (Crossref, RFC Editor, the proceedings page) and cited in ACM format with DOI where one exists.
- **Two independent reviews** by separate AI model runs with no access to the analysis code, that do not see each other's report:
  (1) *academic and factual*: every claim against its cited source, every number against the data file, the
  method against this plan, wording of intervals and differences, overclaiming, limitations;
  (2) *editorial*: clarity, consistency ("websites" for the population, "domains" for results), house rules,
  and phrasing that reads as generated (inflated words, formulaic constructions, summaries that repeat the
  paragraph). Both run after the independent recount; their findings and how each was handled are kept.
- **Style:** plain and specific, as in a measurement paper: one finding per paragraph with its number, n and
  comparison; active voice; no inflated adjectives; uncertainty stated once, precisely.
- **Final read-through** by InfraNest Research before publication.

### 7.4 Prior knowledge of the data

- **Seen before this registration:** the published September 2026 results; the 11 November Tranco pilot and
  dry run of the .nl/.de/.fr lists (they informed section 4 and the expectations); for study 1 and the September
  bridge only operational counters (rows written, the out-of-memory stop at 77,295 domains, 303 and 35 domains
  queued for retry respectively). No
  study 1 measure was tabulated.
- **Study 2:** all analysis decisions (RQ1–RQ6, bands, denominators, expectations, decision rules) are fixed by
  this version 1.0. A CrUX dry run of the same three lists precedes the final scans and its results will be
  seen. Version 1.1 may only add the items listed in section 12.5; it cannot change anything fixed here. Because
  the sector mapping is fixed after the dry run, all sector results are exploratory.

## 8. Analysis plan (fixed now)

**Primary outcomes.** Study 1: the share of mail domains in the CrUX global top 100,000 that are not protected
against spoofing (section 5), with a 95% Wilson interval; denominator: mail domains whose MX and DMARC lookups
were readable after the retry pass. It is reported first, whatever its value. Secondary (study 1): SPF valid, SPF
near the limit, SPF over the limit, the DMARC policy split and "fully configured", overall and per band. Study 2:
the same per country, plus DNSSEC signed and HTTPS trusted per country.

**Study 1** answers RQ1 and RQ2 for the global list and its popularity gradient (bands); DNSSEC, HTTPS and
provider measures are published in its data files only. **Study 2** answers RQ1–RQ6.

**Denominators:** DMARC and "fully configured" over mail domains with readable DMARC (and SPF, for fully configured); SPF
valid over mail domains with readable SPF and DMARC, including those without SPF; SPF near the limit over valid
SPF records; SPF over the limit (more than 10 lookups) over mail domains publishing SPF; DNSSEC states over
signed domains with a readable state, and over all domains with a readable DNSSEC state (both published);
HTTPS measures over answering sites.

**Published per country** (the headline set):
- RQ1 not protected against spoofing; DMARC policy split (the six effective-policy buckets: missing / invalid / partial / none / quarantine / reject)
- RQ2 SPF valid, near the limit, over the limit; fully configured
- RQ3 DNSSEC signed, validates, broken; set beside the registry's zone-wide figure (dated, cited)
- RQ4 HTTPS trusted, expired, ≤ 7 days left; lifetime buckets; top 5 issuers

**Splits:**
- country × band (1–1,000 / 1,001–5,000 / 5,001–10,000 / 10,001–50,000), with cumulative figures alongside. For
  the Tranco bridge list (sensitivity check 3) the tiers are top 100 / 101–1,000 / 1,001+; every top-100 block is
  marked not publishable;
- country × sector, only for cells with n ≥ 100 and with n shown;
- study 1: global × band (the five bands, with cumulative figures alongside), with the trend across bands;
- RQ6: each country band against the global band of the same rank (section 2), with the list dates named.

**Sensitivity checks** (published in the method, never as headlines):
1. **Lists:** the headline measures on the CrUX domains that also appear in Tranco 947N2: in its top 100,000
   (study 1), or among its top 10,000 domains of that ccTLD (study 2).
2. **One per organisation:** groups are connected components of "same label left of the public suffix
   (amazon.de, amazon.fr) AND same mail-provider or DNS-provider company (providers.mjs; if unmatched, identical
   MX or NS host set)"; each group is represented by its member with the best band, ties broken by the
   alphabetically first domain. Alongside, the headline intervals are recomputed as cluster-robust intervals:
   bootstrap over these groups, 2,000 resamples, percentile interval, seed recorded.
3. **September bridge:** the September population (Tranco K9PXW top 10,000) under this plan's code, next to
   the September figures.
4. **Second run:** the headline measures in the full second run (section 7.2, 2a).

Checks 2 and 4 (same population) are reported as the check's estimate and whether it lies inside the headline's
95% interval; if one does not, the text says so next to the headline. Check 1 (a more popular subset) is reported
as its difference from the headline with a Newcombe interval, without pass or fail. Check 3 reports the September
(old analyser) and November (this code) figures on the same 10,000 domains and their difference, and says that
the difference mixes two months of change with the analyser change.

**Statistics:**
- Every block in the data files states its denominator `n` and whether n ≥ 100; headline measures carry a 95% Wilson
  confidence interval.
- The summary warns, and records it, when a run is incomplete (not every listed domain has a row or opted out)
  or mixes rows from different scanner versions. Neither is published.
- **Decision rule for differences:** two shares are called different only when the 95% Newcombe (hybrid Wilson
  score) interval for their difference excludes zero **and** the difference is at least 3 percentage points;
  otherwise the text calls them similar. Where two compared populations share domains, the overlap is stated.
- **Confirmatory vs exploratory:** only the primary outcomes and E1–E3 are confirmatory. All other comparisons
  (bands, countries, sectors, RQ6) are exploratory: every pre-specified cell with n ≥ 100 is published in one
  table whatever its result, and the text calls such comparisons descriptive. A "trend across bands" means the
  band shares with intervals plus the top band against the bottom band under the decision rule; no trend test.
- The populations are complete lists, not samples; intervals express measurement and list-to-list variation.
- **Unreadable domains:** a measure with more than 2% unreadable domains is published with its unreadable share
  next to the headline; above 5% it is not used in the text.
- Prose rounds to whole percentages, the data files to one decimal.

**Never published:**
- individual domains, or lists from which they can be read off;
- cells with fewer than 100 domains;
- rankings of named organisations.

## 9. Ethics and data handling

- **Funding and interests:** the research is funded and run by InfraNest (infranest.io), which sells software
  for managing domains, DNS and monitoring, including SPF and DMARC checks; published totals may be used in its
  marketing. To limit this interest, the definitions, primary outcomes and decision rules are fixed here, all
  pre-specified totals are published whatever their direction, and code and input lists are public.
- **Roles and use of AI:** scan, analysis and text by InfraNest Research. The independent recount and the two
  text reviews (section 7.3) are done by separate AI model runs that have not seen the analysis code or each
  other's reports; this is stated in the published method. Final read-through by InfraNest Research.
- **Legal basis and review:** processing of the few results that concern sole traders rests on legitimate
  interest with research safeguards (GDPR Art. 6(1)(f) and Art. 89: minimal data, totals only, short retention).
  No ethics board reviewed this study; it follows the principles of the Menlo Report and established
  good-practice guidance for internet-wide scanning (public data, low rate, clear identification, opt-out).
- **Small cells:** no published cell, and no difference between two published nested or overlapping cells
  (bands, the CrUX∩Tranco subset, one-per-organisation groups, sectors), rests on fewer than 100 domains.

- **Public data only:** DNS answers through public resolvers (and, from study 2, our own resolver), and one
  ordinary TLS handshake per site, equivalent to one visitor opening the page. From study 2, domains that
  publish an MTA-STS record also get one HTTPS request for that policy file, which exists to be fetched by
  any sender. No logins, no probing for weaknesses, no scanning of ports other than 443.
- **No other use of per-domain results:** they are never used for sales, outreach, lead lists or the
  InfraNest app. Only published totals may be reused (tool benchmarks, glossary pages, product priorities).
- **Scan server hygiene:** automatic security updates; SSH only from an allowlist; a fresh server per scan
  window, destroyed after the data is copied back; raw results encrypted at rest on the server and in the
  one backup kept during a study.
- **No naming:** results are reported as totals by country, band and sector.
- **Internal files:** files that name scanned domains (such as provider values not yet recognised) are used
  to extend the provider table only and are never published; published summaries hold totals only.
- **Per-domain results** stay in the gitignored `/research/` folder, are never shared, and are deleted when
  the next edition is published (at the latest 13 months after the scan). Some domains belong to sole
  traders, which makes those results personal data under the GDPR. Keeping them minimal and short-lived
  is the reason for this rule.
- **Opt-outs** are counted once, without naming them: the scanner stores only a hash of each skipped domain
  (unsalted SHA-256, first 16 hex characters; kept in the internal run.json and never published).
- **Contact and opt-out:** the method section names a contact address for site owners who want to know
  what was measured or want to be left out of future editions.
- **Scanner page:** a public page explains what the scanner does, from where, and how to opt out
  (infranest.io/research/scanner/).

## 10. Outputs

- **Study 1 (English only):** `/research/email-security-2026/` (the year, not an edition number, in the URL, so each edition follows
  the same pattern: `/research/email-security-2027/`).
- **Study 2, full study in English:** the authoritative version, at `/research/email-dns-security-2026/`.
- **Country summaries in NL, DE and FR:** country-first findings, localized charts, a short method,
  and a link to the full study. Reviewed by native speakers, not machine translation.
- **Data:** totals as CSV and JSON under CC BY 4.0; a Zenodo record with a DOI and SHA-256 hashes of every
  file; a Hugging Face dataset card; the scanner and method on GitHub. No per-domain results. The input
  lists themselves (domain and bucket, derived from CrUX, CC BY 4.0) are published, so others can reuse the
  population.
- **Versioning:** data files carry a version; the study page has a changelog and errata list.
- **Citations:** InfraNest Research (infranest.io), 2026. *Email security of the world's 100,000 most-visited
  websites.* — InfraNest Research (infranest.io), 2026. *Email and DNS security of the most-visited Dutch,
  German and French websites.* Edition 1.

## 11. Data collection schedule

| Study | Data collection |
|---|---|
| Pilot and dry runs | 11 November 2026 (Tranco; for QA only, not published as findings) |
| **Study 1** | Main scan **13 November 2026** (19:22–21:40 UTC); retry pass 14 November; full second run and second-location HTTPS re-check 15 November. September bridge (Tranco K9PXW): 13 November, retry 14 November |
| **Study 2** | CrUX dry run of the three country lists in November 2026 (QA only, not published as findings); final scans of the three country lists and the global top 100,000 within one 72-hour window in **late November 2026**, retry pass 24 hours later, full second run 36–48 hours after the main scan. The study 2 additions (section 5) and the exact window are fixed in version 1.1 of this protocol, registered before the final scans |

Planned publication: study 1 in November 2026, study 2 in December 2026.

## 12. Decisions recorded before registration

1. **DMARC `t=` flag:** RFC 9989 §4.7 defines `t=y` as applying the policy one level below `p=` (section 5).
2. **Population source:** CrUX (section 4); Tranco only for the robustness check and the September bridge.
3. **Registrar:** not measured per domain. DENIC's terms forbid high-volume automated querying, SIDN warns
   against bulk collection and limits its WHOIS, and AFNIC limits and filters automated queries. Where registrar
   shares are wanted, the registries' own published statistics are cited.
4. **Registry DNSSEC figures:** cited from the registries (section 3) and re-fetched on the scan date.
5. **Fixed in version 1.1, before the study 2 scans:** the sector mapping (Wikidata categories, section 4), the
   own resolver and the second location (section 6), the DANE and MTA-STS measures (section 5), and the exact study 2 scan
   window (section 11).

## 13. Risks

| Risk | Mitigation |
|---|---|
| Popularity lists include domains that never send mail (CDNs, APIs, sites without email) | Email measures use mail domains only; the "no MX" count is published |
| Geo-blocking or rate limits make some sites refuse the handshake | Report "no answer" separately from "untrusted"; do not count it as a failure |
| Resolver disagreement or temporary SERVFAIL | Two resolvers; one retry after 24 hours; unreadable domains excluded and counted |
| RFC 9989 not yet implemented by all receivers (those following RFC 7489 ignore `t=`) | Enforcement uses the RFC 9989 effective policy; the policy as published (`p=`) is reported alongside; no claims about delivery |
| A striking number turns out to be a bug | Hand check and independent recount before publishing; corrections policy after |
| Wikidata sector coverage is uneven between countries | Show coverage; publish sector cells only with n ≥ 100 |
