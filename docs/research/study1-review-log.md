# Study 1: review log (protocol 1.0, section 7.3)

The two independent reviews of the study page, and how each finding was handled. Both reviews ran on
15 November 2026 as separate AI model runs. They worked from the page as a reader sees it, and neither saw the
analysis code or the other's report:

- **Review 1, academic and factual:** the page, the data file, the protocol, the references, the implementation
  notes and the September file, with web access to check sources.
- **Review 2, editorial:** the page and section 7.3 of the protocol only.

The full reports are kept internally with the hand-check evidence. They quote no domain.

**Handled:**
- **Done:** changed on the page, in the data file or in the notes.
- **Partly:** the main point was taken, the rest not, with the reason.
- **Not done:** with the reason.
- **Later:** belongs to a step that is still open, such as test-retest, the deviations list or the PDF.

## Review 1: academic and factual (6 must fix, 18 should fix, 12 consider)

| # | Finding | Handled |
|---|---|---|
| 1 | "41% fully configured": prose rounded from the one-decimal value | **Done.** Prose now rounds from k/n everywhere (`share0`): 40%. Implementation note 17 |
| 2 | "3% over the limit": same error | **Done** (2%) |
| 3 | "Higher in each band than the band before" breaks the decision rule (neighbouring bands +2.4, CI −0.3 to +5.0) | **Done.** The claim is removed. The text lists the band shares only; top against bottom stays the only comparison |
| 4 | "None of these asks … to quarantine or reject" is false for partial | **Done.** Now "not asked to quarantine or reject every forged message" |
| 5 | Recount overstated | **Done.** The page says what the recount saw (plan, scanner source, raw results, no analysis code) and gives the counts recomputed, identical, differing and not recomputed. Note 16's last line corrected |
| 6 | "Who was left out" adds up to 80,308; 227/230/231 | **Done.** Added the 4 domains whose own DNSSEC is broken; the six counts now add up to 80,312. The flag counter is fixed (230 → 231, note 17) |
| 7 | "No record" includes the 340 with two records | **Done.** The label is now "No record (or two)", and the prose and method say so |
| 8 | Invalid `sp=` is not ignored by receivers | **Done.** Now: `pct` is ignored as receivers do; `sp=` by our choice, because subdomains are out of scope |
| 9 | Receiver behaviour presented as measured | **Done.** "As the standard asks receivers to read it", "ask receivers to act on", "the limits RFC 7208 sets" |
| 10 | "One more include and they break" | **Done.** Now "adding one or two sending services can make them fail" |
| 11 | "Fails for every receiver" | **Done.** Now "gives a permanent error, so SPF cannot pass" |
| 12 | "Most accurate" goes beyond [17] | **Done.** Now "of the lists evaluated in 2022, matched Cloudflare's traffic data best"; "still most accurate" removed |
| 13 | CrUX limitation understated | **Done.** Added sync and usage statistics, desktop and Android only, indexable, undisclosed threshold |
| 14 | Check 1 reported incompletely | **Done.** Gives the shared-domain count, not protected and fully configured with differences, the nesting and independence remark, and inside/outside the headline interval. The other measures are in the data files |
| 15 | September bridge: overlap and definition changes | **Partly.** The text now names both definition changes, says both columns are the same 10,000 domains (the interval treats them as independent, so it is wider than a paired one), and says differences use unrounded shares. `overlap` stays 0 in the data: the field means shared domains between two compared populations at one time; here the same list is measured two months apart |
| 16 | Cluster interval mislabelled | **Done.** Now "allowing for shared setups, the interval itself widens to …" |
| 17 | Meaning of intervals for complete lists | **Done.** Added to Statistics |
| 18 | Bucket counts read as cumulative | **Done.** Now given per band |
| 19 | "Only that measure loses it" contradicts section 4 | **Done.** The two exclusion rules are stated as the protocol words them |
| 20 | "Gets the same verdict" unsupported | **Done.** Now "uses the same analysers"; the effective policy and totals are computed afterwards |
| 21 | Pre-registration timing; public commit | **Done.** Timing stated as in protocol 7.2 (2b), with the start time from the data file; commit with its public tag `scanner-<commit>` |
| 22 | No funding, interests or roles statement | **Done.** New paragraph "Funding, interests and roles", from protocol section 9 |
| 23 | Missing limitation: inherited DMARC policies | **Done**, with its direction ("can overstate not protected slightly") |
| 24 | TXT-escape note stronger than note 14 | **Partly.** Re-query caveat added. The claim "no published share changes at one decimal" is kept: the record is in band 50,001–100,000, where no share moves (checked: invalid 0.1, none 34.7, published none 45.8 unchanged). The page now says "also in that record's band" |
| 25 | Rounding rule vs one-decimal numbers in text | **Done.** The rule is restated: shares whole percent; intervals, differences and checks one decimal |
| 26 | Hand check: Quad9 vs openssl; disagreements; 100/100 lower bound | **Partly.** Tool wording corrected (openssl used the server's resolver). The disagreements stay summarised, with the detail in note 13. The Wilson lower bound was not added: the target is agreement in the sample, as the protocol words it |
| 27 | Recount checks aggregation, not classification | **Done.** Said on the page |
| 28 | Check 2 representative drops 171 groups | **Done** as documentation: note 8 now explains the rule (chosen among all members, as section 8 words it) and its effect. Not changed after seeing results |
| 29 | "Not protected by DMARC"; RFC 7489 ignores `t=`; no-MX domains can be spoofed | **Done.** All three on the page (key number, DMARC paragraph and limitations) |
| 30 | Tatang et al.: say which domains the 11% refers to | **Later.** To check against the paper before the PDF |
| 31 | References: RFC 9989 "Ed."; ACM style for RFCs; Tranco K9PXW reference | **Later**, with the PDF build (references.csl.json) |
| 32 | CIs for near and over limit in the band table | **Not done.** The plan gives intervals for headline measures in the text. The data files hold every interval |
| 33 | Numbers in implementation notes are free text | **Not done.** They are hand-filled fields of the data file, which section 7.3 allows ("rendered from the study's data file") |
| 34 | Differences and CIs for the other band comparisons | **Done** |
| 35 | Deviations section content | **Later**, at the read-through |
| 36 | Quotable sentences lack a population | **Done** |

## Review 2: editorial (6 must fix, 26 should fix, 13 consider)

| # | Finding | Handled |
|---|---|---|
| 1 | Intro "changes from the top 1,000…" | **Done** |
| 2 | Websites → domains → mail domains never explained | **Done.** One paragraph under the headline |
| 3 | "As receiving mail servers apply it" vs Limitations | **Done** (see review 1, #9) |
| 4 | DMARC not explained at first use; "None of these" | **Done** |
| 5 | Two names for the primary outcome; spoofing undefined | **Done.** "Not protected against spoofing", defined in the headline |
| 6 | n line unit; CI not written out | **Done** |
| 7 | Check 2 sentence repeated, reads as "headline wrong" | **Partly.** Reworded ("Many organisations run several domains with one setup …"). It stays next to the fully configured number as well, because section 8 requires it next to each headline measure outside its interval |
| 8 | Key number repeats the headline | **Not done.** The key-number cards are meant to be quoted alone |
| 9 | Key numbers have no population | **Done** |
| 10 | Fully configured vs 100% − 57% | **Done** |
| 11 | "One more include and they break" | **Done** |
| 12 | DMARC heading is a slogan and wrong | **Done** |
| 13 | DMARC rules paragraph overloaded | **Done.** Split into two paragraphs |
| 14 | "Of the rest" denominator | **Done**, with the tie back to the 57% |
| 15 | As-published shares: denominator | **Done**, with n |
| 16 | "Close to" vs "near" the limit | **Done** |
| 17 | DNS lookups unexplained; "fails for every receiver" | **Done** |
| 18 | "Publish none"; over-limit name; near limit missing | **Done** |
| 19 | CrUX unnamed in the bands section | **Done** |
| 20 | Rule repeated; direction of the difference | **Done** |
| 21 | "Higher in each band" breaks the rule | **Done** (see review 1, #3) |
| 22 | "Also has a higher share" | **Done** |
| 23 | E2 label; other expectations | **Done.** E1 and E3 named as study 2 |
| 24 | September note wording | **Done** |
| 25 | September rows without denominators | **Done** |
| 26 | Site owners: what to do | **Done.** Three points in the "Check your own domain" box. The two boxes are not merged, to keep the page order |
| 27 | "Most accurate" three times | **Done** |
| 28 | Five-item sales list in prior work | **Done** |
| 29 | Bucket counts; origins | **Done** |
| 30 | MX unexplained | **Done** |
| 31 | Effective policy as a numbered list | **Not done.** The table cell stays one rule, and the DMARC section explains it in prose |
| 32 | DKIM, alignment, HSTS | **Done.** HSTS removed |
| 33 | "Could not be read on both" | **Done** |
| 34 | Counts add up to 80,308 | **Done** (see review 1, #6) |
| 35 | "Rare states" vague | **Done** |
| 36 | Recount sentence contradicts itself | **Done** |
| 37 | Check 1 sentence | **Done** |
| 38 | Wilson and Newcombe unexplained | **Done** |
| 39 | Rounding rule broken | **Done** |
| 40 | Small-cell unit | **Not done.** "Domains" is correct: the rule applies to all measures, not only email |
| 41 | Dangling modifier in a note | **Done** |
| 42 | "Browsing is local"; repeated DKIM line | **Done** |
| 43 | "Send no mail" vs MX | **Done** |
| 44 | Site-owner and About wording | **Done** |
| 45 | Navigation labels vs headings | **Later**, with the PDF and layout pass |

## Final check round, 16 November 2026 (after the final results)

Three more separate AI model runs, each without the analysis code or the others' reports, on a frozen
snapshot of the built page, the PDF report, the figure CSVs, the share image and the data file:

- **Numbers:** every number on the page, in the report, the CSVs and the share image against the data file
  and the constants. About 3,500 values checked; **no wrong result value**. All 436 data blocks recompute
  exactly, all 677 CSV cells match, the left-out counts add up to the list, and every verdict is right.
- **Sources:** every cited claim and every reference, with the sources fetched (none from memory). All 19
  entries and 14 DOIs verified; three sentences said more than their source.
- **Readability:** the page read as a journalist, a site owner and an academic reader.

### Numbers (7 blockers, 11 minor)

| # | Finding | Handled |
|---|---|---|
| N1 | "Data collected 13–14 November" leaves out run 2 and the second location, which also give published numbers | **Done.** 13–16 November in the header and JSON-LD; the method and report name each period (main scan, run 2, second location) |
| N2 | "Implementation note 16/18" pointed to notes the page does not show by number | **Done.** Notes on the page are numbered; the full numbered notes are linked (to be published in the research repository before launch) |
| N3 | The 57% key-number card lacked the check 2 note that section 8 requires | **Done** |
| N4 | Report abstract: 40% without n, CI or check 2 note; SPF shares on an unnamed base | **Done.** n and CI for every abstract share, the base named, the check 2 note added |
| N5 | Method numbers typed by hand (20 per rare state, 3 points, 2% and 5%, 0.80, versions 1.0 and 0.9) | **Done.** All in `METHOD` (constants.ts) |
| N6 | "10 of the 16 insecure zones" (note 15) is a share with a base under 100 | **Not done.** It is a count in a report of a scanner error, not a published result; the minimum-cell rule covers result cells. No zone is named |
| N7 | Check 2 reported for one measure only (check 4 for all five) | **Done.** All five, each with its interval allowing for shared setups |
| N8–N18 | Table 1 SPF base n; "every share is of the mail domains"; E2 without n; CSV promise "with interval"; one decimal in the quality checks | **Done** |
| | CSV numbers without trailing zeros | **Not done.** They are numbers, not text; any tool reads 24 as 24.0 |
| | The September difference records `overlap: 0` | **Not done.** It is the interval's input: the page states the two columns are treated as independent samples |
| | "In short" and the share image give 57% without n | **Not done.** Skim summaries; the headline with n, CI and the check 2 note follows directly |
| | Changelog shows 1.0 while the data file's version is empty | **Later**, at sign-off |

### Sources (3 blockers, 14 minor)

| # | Finding | Handled |
|---|---|---|
| S1 | Ruth et al.: the paper finds most *websites* are popular in one country, not that people mostly visit local sites | **Done** |
| S2 | Tatang et al.: the 11% needs its scope (top one million of three lists, May 2020) and the 2015 baseline | **Done**, citing Durumeric et al. 2015 for the baseline |
| S3 | "Domains without a usable MX receive no mail" is wrong (implicit MX, RFC 5321) | **Done.** "Publish no mail server of their own" |
| S4 | RFC 9989 and RFC 7489 editors need "Ed." | **Done**, as in the RFC Editor's citations |
| S5 | RFC 7489 not cited for pct=0, t= being ignored, invalid pct | **Done** |
| S6 | `ptr` missing from the lookup terms | **Done** |
| S7 | CrUX reference should point to the methodology page; the bucket sentence needs a citation | **Done** |
| S8 | Tranco K9PXW (September list) has no reference; 947N2 dated n.d. | **Done.** K9PXW added; both dated |
| S9 | "Korczyński" diacritic | **Done** |
| S10 | Wilson, Newcombe, Cohen, the Menlo Report and the scanning guidance uncited | **Done.** Five references added, re-checked against Crossref and USENIX; Newcombe named as the hybrid Wilson score method |
| S11 | RFC 9989 reads a record without p= as none; we count it invalid | **Not done.** Both are "not protected", so no number changes; noted for protocol 1.1 |
| S12 | The 2-void-lookup limit is a SHOULD in RFC 7208 | **Not done.** The definition is the registered one (protocol section 5); noted for protocol 1.1 |
| S13 | Pre-registration as a reference entry | **Not done.** It is linked by DOI where it is named |
| S14 | Own citation: version and DOI in all formats, one report-type wording, reference-manager import test | **Later**, with the Zenodo DOI at sign-off |

### Readability (22 should fix, 18 nice to have)

| # | Finding | Handled |
|---|---|---|
| R1 | "Registered before the scan" contradicts the timing note | **Done.** "Before any result was computed" |
| R2 | Three SPF numbers on different bases side by side | **Done.** Labels and caption name the bases |
| R3 | Headline worded four ways | **Done.** "Not protected against spoofing by DMARC", with the delivery caveat beside it |
| R4 | "The most-visited websites do better" (a share of mail domains) | **Done** |
| R5 | Terms and the list source explained too late | **Done.** CrUX and "mail domains" in the standfirst; "top 1,000 (band 1–1,000)" on first use |
| R6 | Promo banner on the research page | **Done.** No banner and no sales nudges on /research |
| R7 | Site-owner DMARC advice incomplete (no rua=) | **Done** |
| R8–R10 | "Fully configured" overclaims; effective vs published policy wording | **Done** |
| R11–R13 | Unnumbered sensitivity checks; kappa unexplained; checks without purpose | **Done** |
| R14–R20 | September wording; "this work"; organisation note; definition as steps; DMARC paragraphs; companion study introduced once; report qualifier | **Done** |
| R21 | Share-image alt text and meta description | **Done** |
| R22 | No Ethics section on the page | **Done** |
| R23–R39 | Band/bucket, websites/origins, captions, legend labels, nav labels, small wording, Table 1 header | **Done** |
| R28, R31, R32 | Fewer summaries at the top; section order; fewer tool links | **Not done.** Kept for journalists and site owners; the tool links are the intended light mention |
| R33 | About repeats the funding description | **Not done.** The owner chose this description |
| R40 | Name the AI model | **Later**, owner's decision |

## Delta check, 16 November 2026 (the final round's fixes only)

One more separate AI model run, on the changed text only, with every new reference fetched at its source.
All numbers in the changed text match; the six new references are exact and support their sentences.

| # | Finding | Handled |
|---|---|---|
| D1 | The 2015 DMARC baseline (0.97%) in Tatang et al. comes from Foster et al. 2015, not Durumeric et al. (1.1%) | **Done.** Cites Foster et al. |
| D2 | Method said "retried after 24 hours" while the deviation says about 22 | **Done.** "About a day later (the plan says 24 hours; see the deviations)"; the deviation gives the reason: retries were timed from each scan's start, not its end (the September re-scan too) |
| D3 | Implementation-notes link is dead | **Later.** Published in the research repository on launch day (they contain results) |
| D4 | "10 of the 16 insecure zones" (note 15 on the page) | **Done.** "Most of these zones"; the count stays in the notes file |
| D5–D14 | RFC 9989 cited for t=y/pct=0; deviations dated with reasons; E2 with n and CI in the abstract; "next to its headline number"; "none … can only ask for reports"; SPF bar base; "name no usable mail server"; both test-retest thresholds; one Table 1 label; JSON-LD and meta descriptions no longer overstate quarantine | **Done** |

## Owner's read, 16 November 2026

| # | Finding | Handled |
|---|---|---|
| O1 | RFC 7489 is obsolete (RFC 9989, 9990, 9991) | **Done.** Kept on purpose (it is the source for `pct` and for receivers that still follow it); the reference now says "Obsoleted by RFC 9989, RFC 9990 and RFC 9991" |
| O2 | RFC 7208 has updates (RFC 7372, 8553, 8616) | **Not needed.** None changes a rule this study uses; the RFC Editor's citation format lists no updates |
| O3 | Tranco asks for the paper, the list's permalink and its generation date | **Done.** Both lists now say "generated on …" in the text (dates from the reference data); the proceedings title matches Tranco's requested citation |

## Outside review, 20 November 2026

An outside, AI-assisted review of the draft PDF (16 November), read by the owner, then checked here
against the data, the CrUX file and the RFC texts before anything changed. Its follow-up asked for one
headline wording, which is used with one correction (see X1).

| # | Finding | Handled |
|---|---|---|
| X1 | "Not protected against spoofing" overstates a DNS-policy measure | **Done.** Full headline (abstract, results, page headline): "57% of the mail domains studied lacked a DMARC policy requesting quarantine or rejection for all messages that fail DMARC, under the study's rules". Short form (page summary, meta, share image): "57% of mail domains … don't ask receivers to quarantine or reject mail that fails DMARC". The reviewer's "of the domains studied" was corrected to "mail domains": 57% is of the 55,106 mail domains, not the 80,312 domains |
| X2 | "Fully configured" claims too much (DKIM not measured) | **Done.** "Valid SPF and enforced DMARC"; primary outcome named "No enforcing DMARC policy"; data keys unchanged |
| X3 | Bands at 5,000 and 50,000 may not be CrUX buckets (zakird README lists 1k/10k/100k/1M) | **False alarm.** The pinned file `global/202610.csv.gz` (SHA-256 410165bb…) has exactly the rank values 1,000, 5,000, 10,000, 50,000, 100,000, 500,000, 1,000,000. One sentence added: the boundaries are the rank values in the list file |
| X4 | Reference [8] should pin the commit and CSV | **Already done** (commit a67d0c8, data/global/202610.csv.gz) |
| X5 | RFC 9989 reads a record without `p=` as none; `pct` is RFC 7489 only; show RFC 9989-only result | **Done.** Sensitivity check 5 (post hoc): 30,660 / 55,106 = 55.6%, −870, outside the headline interval, note next to the headline. The reviewer's reconciliation (30,688, 55.7%) missed 29 `p=quarantine; pct=0` records (none → quarantine); the final check added RFC 9989's invalid-`sp=` rule (1 record, quarantine → none). Known-answer tests added. Implementation note 19 |
| X6 | Inherited (higher-level) policy beside the definition | **Done.** "Domain-level classification" in the definition, pointing to the limitation |
| X7 | SPF: what does the scanner count across branches? Void lookups = SHOULD | **Done.** Every term in every branch = the cost of a message that matches nothing before `all`; over the limit fails for some messages, not necessarily all; 2 void lookups = RFC 7208's recommended default |
| X8 | MX: "hosts no sender can reach" vague; implicit MX | **Done.** Criterion stated (every host `localhost` or a name without a dot); implicit MX in the definition and limitations |
| X9 | Wilson sentence wrong (measurement error, other list) | **Done.** Sampling uncertainty only; other sources via hand check, test-retest, check 1 |
| X10 | Tranco check: nested groups | **Done.** Registered nested comparison kept; disjoint in/not-in Tranco added (post hoc): 51.3% against 66.4% no enforcing policy |
| X11 | September: same list, paired | **Done.** Registered method kept; text says the interval does not account for the pairing |
| X12 | Registration after collection began: state up front with the time | **Done.** Abstract and 4.7: registered 13 Nov 2026 23:16 UTC (OSF API), collection began 19:22 UTC |
| X13 | "One per organisation" stronger than the grouping can show; representative; "outside the interval" a poor test | **Done.** "Domain group", representative stated, "estimates under a different weighting"; the registered note next to the headline stays (protocol section 8) |
| X14 | "Similar" without an equivalence test | **Done.** "No difference by our rule (not a test of equivalence)" |
| X15 | 2015 baseline source and denominator | **Done.** Foster et al. 0.97% of the top million (January 2015), as reported by Tatang et al.; Tatang "up to 11.5%" (May 2020), tenfold rise on Alexa Jan 2015–Dec 2019 (checked in the full text) |
| X16 | RFC section numbers | **Done.** RFC 9989 §4.7, §4.10, §4.10.1, §5.4, App. A.6; RFC 7489 §6.3, §6.6.4; RFC 7208 §4.6.4 |
| X17 | Recent related work (EC report; post-Google-guidelines study) | **Done.** Kondo et al., TMA 2025 (full text read; definition differences stated) and Kouliaridis & Kounelis, JRC 2025 (Publications Office record) |
| X18 | Figure 1 not in the data list; blank last page | **Done.** `figure-1.csv`; the last page was a print artefact, gone |
| X19 | PSL version and private section | **Done.** Version 2026-11-11_13-52-29_UTC, commit 7786aac, ICANN and private sections |
| X20 | "Independent recount" / "academic and factual" reviews read as external review | **Done.** "Separate recount (AI-assisted)"; reviews "AI-assisted … not external peer review"; the outside review is mentioned. No model named (owner's choice) |
| X21 | Abstract too long and repetitive; "It held"; "The test-retest tests" | **Done.** SPF limit split moved out of the abstract; second grouping note shortened; "the data met this expectation"; "measures how much" |
| X22 | New title | **Not taken.** Title kept (registered, URL); subtitle "SPF and DMARC among the CrUX top 100,000" added |

### Follow-up from the outside reviewer, 20 November 2026

| # | Finding | Handled |
|---|---|---|
| X23 | §5.3 equates the scanner's all-branch count with the cost of a message reaching `all`; needs evidence | **Done.** Checked `_spf.js`: the scanner also counts terms after an `all` (never evaluated) and counts a macro include as one lookup without following it, so the equivalence does not hold exactly. Text now: the scanner counts DNS-querying terms across all branches; a receiver applies the limit to the terms evaluated for a message; "over the limit" is a finding under the scanner's counting rule |
| X24 | "RFC 9989 only" suggests full processing (no `np=`, no policy discovery) | **Done.** Check 5 is "RFC 9989 handling of the measured records", and says it is not full RFC 9989 processing |
| X25 | Tranco nested comparison: "conservative" too firm | **Done.** "Does not account for the overlap; for a subset of the whole, this usually makes it wider" (as in §5.5) |
| X26 | Introduction: "act on a forged message", "fails those checks" | **Done.** DMARC described as From-domain alignment with an SPF- or DKIM-authenticated domain, and a published preference for messages that fail DMARC; page's DMARC section and hero aligned |
| X27 | Abstract: "which drop pct" reads as if it refers to the records; Kondo's "5% increase" has no unit | **Done.** "Applying RFC 9989's rules to the measured records gives 55.6% … The newer standard ignores the legacy pct tag."; Kondo: "the share of domains publishing DMARC rose" (the paper does not say points or relative) |
