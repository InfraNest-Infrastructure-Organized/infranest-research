# Study 1: implementation notes

How the analysis code (`scripts/research/lib/analysis.mjs`, `lib/summarise.mjs`, `lib/sensitivity.mjs`,
`summarise-cc-security.mjs`, `test-retest.mjs`) applies the registered protocol, version 1.0
(OSF, doi:10.17605/OSF.IO/P6YTU, `docs/research/email-dns-2027-plan.md`). It is used for the
published method: the "Implementation notes" there come from this file, and only items marked
**(b)** can need an entry under "Deviations".

Each note gives the protocol section, the choice the code makes, and its kind:

- **(a) clarification:** the protocol's wording already decides the case. The note only spells out how.
- **(b) open choice:** the protocol did not decide this. We made the choice before any study 1 result was computed.

Notes 1–12 were written before any study 1 result was computed and contain none. Notes 13–19, and the
effect figures added to note 8, record what the checks and reviews found afterwards.

## Measures (section 5)

1. **DMARC: `p=none` with `pct` 1–99** (section 5, "DMARC enforced"). Counted as effective **none**.
   The protocol defines what `pct` 1–99 means for `p=quarantine` and for `p=reject`. For
   everything else it says "otherwise `p=`, lowered by one level when `t=y` and/or `pct=0`". `p=none`
   has no lower level, so it stays none. **(a)**

2. **DNSSEC: "zone validates"** (section 5, "DNSSEC zone validates"). Counted as *valid* plus
   *broken, partly*, where *broken, partly* includes only confirmed cases. A zone with a partial
   break seen in only one scan is in the state *broken, unconfirmed* and is not counted as
   validating. The protocol lists *broken, unconfirmed* as a state of its own and defines "zone
   validates" as valid + broken, partly. **(a)**

3. **DMARC: records with `pct` below 100, counted apart** (section 5). Counted among domains with
   exactly one DMARC record, using the `pct` a receiver applies: an invalid `pct` counts as 100,
   and `pct=0` counts as below 100. The protocol says to count such records apart but does not
   name the base or say how `pct=0` and invalid values are treated. **(b)**

4. **SPF: a lookup error without the scanner's "unreadable" flag** (sections 4 and 5). An SPF result
   that carries a DNS-error finding is treated as unreadable even when the scanner did not flag it.
   It is never treated as valid. The protocol says a record that cannot be read "makes SPF
   unreadable … never valid". **(a)**

5. **DMARC: what counts as "invalid"** (section 5). Exactly the protocol's list, as reported by the
   frozen analyser: invalid characters, a missing `;`, no `p=`, or a `p=` value other than none,
   quarantine or reject. A misspelled or unknown tag elsewhere in the record does not make it
   invalid. **(a)**

## Statistics and flags (section 8)

6. **Unreadable shares: denominators and level** (section 8, "Unreadable domains"). Each measure's
   unreadable share is computed over its own eligible domains:
   - **email (MX or `_dmarc`):** all domains not removed;
   - **SPF:** mail domains whose DMARC was readable;
   - **DNSSEC (DS, and state):** all domains not removed;
   - **HTTPS:** domains with a public address, plus those whose address could not be read.

   Flags (more than 2% shown, more than 5% not used in the text) are computed for the whole list,
   not per band. The protocol sets the thresholds but neither the denominators nor the level. **(b)**

## Sensitivity checks (section 8)

7. **Check 1, CrUX ∩ Tranco 947N2.**
   - **Matching (b):** a CrUX domain is "also in Tranco" when its registrable domain appears exactly
     as written among the first 100,000 entries of list 947N2. A different version of the Public
     Suffix List could make a few names fail to match.
   - **Reporting (a):** the subset is part of the headline population. It is reported as a
     difference with a Newcombe interval, as the protocol prescribes, and the number of shared
     domains is stated next to it, because that interval assumes independent samples.

8. **Check 2, one per organisation.**
   - **The label left of the public suffix (a):** this is the first label of the domain, because
     every row already is a registrable domain.
   - **Provider match (b):** two domains share a provider when they share a mail-provider or
     DNS-provider company in `providers.mjs`. A role falls back to "identical MX (or NS) host set"
     only when none of that domain's hosts in that role match a company. When some hosts match and
     some do not, only the matched companies are compared.
   - **Representative (a):** the member with the best band, ties broken alphabetically, chosen among all
     members of the group, as section 8 words it, not among the members in a measure's population. When
     that member is not in a measure's population (for email: not a mail domain), the group is not in that
     measure's estimate. For "not protected" this leaves out 171 of the 51,519 groups that contain a mail
     domain (n = 51,348). Choosing among the members in the population would keep them; we did not, because
     the plan names the rule.
   - **Bootstrap (b):** 2,000 resamples of whole groups with replacement, using a seeded
     pseudo-random generator (mulberry32). The interval is the percentile interval, taken as the
     values at positions ⌊0.025·N⌋ and ⌊0.975·N⌋ of the sorted resamples. The seed is passed
     explicitly and recorded in the summary.

9. **Check 3, September bridge: what is compared.**
   - **Measures (b):** the protocol asks for "the September figures" next to this study's figures
     on the same 10,000 domains, but not which ones. We compare the figures September published
     for mail domains: SPF published; DMARC published; SPF over 10 lookups and 8–10 lookups (both
     of SPF-publishing domains, September's definitions); the published `p=` split; and
     September's "protected" next to this study's "fully configured", labelled as different
     definitions.
   - **Remaining differences in definition (a):** these are stated in the table. September counted
     a DMARC record as published even when there were two; this study requires exactly one.
     September's SPF base is all mail domains; this study's is mail domains whose SPF and DMARC
     could be read.

10. **September's counts are exact (section 8, check 3).** September's figures are counted from its own
    per-domain results (`data/research/email-auth-2026-09/results.ndjson.gz`, Tranco K9PXW top
    10,000) with September's own definitions (`scripts/research/summarise-email-auth.mjs`).
    - Every compared share, and the number of mail domains, reproduces the published
      `public/research/email-auth-2026-09.json` exactly.
    - The code checks this on every run and records any mismatch. A mismatch would never be replaced
      silently.
    - Nothing in check 3 is approximate. This replaces an earlier draft of the code, which rebuilt
      September's counts from the rounded published shares. **(a)**

## Test-retest (section 7.2, 2a)

11. **Measures and pairs** (section 7.2, 2a). Agreement is reported for: mail domain (MX), effective
    DMARC policy, DMARC enforced, SPF state (none / valid / invalid), SPF near the limit, fully
    configured, DNSSEC signed, DNSSEC state, HTTPS outcome (trusted / untrusted / no answer) and
    HTTPS trusted.
    - **Pairs:** each measure compares only domains that are in its population and readable in
      both runs.
    - **Kappa:** when a measure shows a single value in both runs, Cohen's kappa is undefined. It
      is reported as empty, and the flag then rests on the share identical.

    The protocol names the effective DMARC policy as an example of a categorical measure but does
    not fix the list or the pairing. **(b)**

## Expectations (section 2)

12. **E3 "a majority of that country's bands"** (study 2). Counted as more than half of the
    country's bands with at least 100 valid SPF records. A band whose global counterpart has fewer
    than 100 cannot be tested and counts as "not higher". **(b)**

## Hand check and recount (section 7.2, 1 and 2), 14 November 2026

Notes 13–16 record what the two checks found. The hand check ran on the main scan, before the retry pass;
the figures in notes 14–16 are those of the final file, after it. Marked **(c)**: an error or limitation
found by a check. Per-domain evidence stays internal (`research/study1-global-handcheck/`,
not in git), as section 9 requires.

13. **Hand check.** 100 random readable domains (seed 20261114) plus up to 20 per rare state (DMARC
    invalid, SPF over the limit, DNSSEC broken: all 3, certificate expired), checked about 15 hours after
    the scan. The checks ran from the scan server against Quad9, a resolver the scanner does not use:
    checkdmarc 6.0.4 for SPF and DMARC; `dig` and `delv` (BIND 9.20) for DNSSEC; `openssl s_client` for
    HTTPS. Beyond the protocol, 20 DNSSEC-valid and all 16 DNSSEC-insecure domains were added (seed
    20261115), because a random 100 holds few signed zones.
    - **Random 100: 100% agreement on every measure** (MX, SPF state, SPF lookup bracket, SPF over the
      limit, effective DMARC policy, DNSSEC state, HTTPS outcome, expired). The one raw difference was
      the check's own mapping: a `_dmarc` name holding only an unrelated TXT record, which checkdmarc
      reports as an error and the protocol counts as "no record".
    - **Rare and extra strata.** Every difference was traced:
      - checkdmarc accepts two records with a missing `;` that section 5 counts as invalid. This is a
        difference of definition.
      - checkdmarc stops at the first SPF error, so it gives no lookup count for two records it also
        judges invalid.
      - Quad9 failed on one domain's SPF, and delv timed out or hit "end of file" on Quad9 for
        several record sets. All of them validate through Cloudflare and Google.
      - delv "deadlocks" on a CNAME at a zone apex.
      - The check's `openssl` used the server's system resolver, which returned no address for one
        host. Connected by the address the scanner used, the certificate verifies.
      - The two partly broken zones that disagreed still fail validation on both of the scanner's
        resolvers (Cloudflare EDE 6), so the scanner's "broken partly" stands. Quad9 does not reject
        them.
      - The two errors below.
    - Target met: at least 98% per measure on the random sample, no measure affected by a scanner error.
      **(c)**

14. **TXT escapes are not decoded (scanner error, no effect on any headline).** DNS-over-HTTPS JSON returns
    TXT data in presentation format, so a tab arrives as the four characters `\009`. The scanner does not
    decode `\DDD` and `\"`.
    - The 86 DMARC and 159 SPF records with a syntax finding were re-queried. 18 and 16 of them contain
      escapes.
    - Only one changes class: a DMARC record that separates its tags with tabs, which RFC 7489 allows.
      It is counted as invalid and should be `p=none`. Both classes count as "not protected", so the
      primary outcome does not move. Invalid is 51 and should be 50; none is 17,750 and should be
      17,751.
    - The other escapes are line breaks, zero-width or non-breaking spaces and stray backslashes. RFC
      7489 (DMARC) and RFC 7208 (SPF, terms separated by spaces only) do not allow them, so the
      scanner's verdict stands, or the escape sits after `p=` and changes nothing.
    - A record that starts with an escape would have been missed altogether. None was found among the
      re-queried records, but the full list was not re-queried.
    - Study 1 publishes the scanned values and states this. The fix (decode presentation format) goes
      into the scanner before study 2, under protocol 1.1. **(c)**

15. **"Insecure" rests on the first resolver that answers.** The scanner calls a signed zone insecure when
    the SOA answer lacks the AD flag. It takes the first resolver that answers, which is Cloudflare
    unless Cloudflare fails.
    - Re-queried on 14 November, 10 of the 16 insecure zones were validated by Google and by Quad9,
      but not by Cloudflare, which gave no extended error. The other 6 were insecure on all three.
    - Effect: DNSSEC-valid is 5,368 of 5,389 signed domains with a readable state (99.6%). With the 10
      counted as valid it would be 5,378 (99.8%). Insecure falls from 16 to 6.
    - Study 1 publishes the scanned state with this note. It does not reclassify from a later
      re-query, which would mix measurement times.
    - For study 2 (protocol 1.1), insecure requires that neither resolver validates. **(c)**

16. **Separate recount (AI-assisted).** A separate AI model run, which saw only the protocol, the scanner sources (for
    field meanings) and the raw results, wrote its own analysis (Node, no shared code).
    - Run on the main scan and again on the final file, after the retry pass. Both times, **every number
      both programs compute matches exactly.** On the final file that is 556 of the summary's 742 counts,
      392 of them distinct: all bands and cumulative tiers, the six effective-policy classes, not
      protected, SPF, fully configured, the DNSSEC states, HTTPS, E2, and checks 1 and 2.
    - The other counts are ones the recount does not compute: the SPF and DMARC breakdowns (permanent
      errors, `+all`, invalid `sp`, and the like), the pooled rank 1,001+ tier, the extras, and check 3,
      which needs September's files.
    - Remaining differences:
      - "Test mode" here counts `t=y` or the legacy `pct=0` (119); the recount counted `t=y` only (17).
        The text must name both.
      - One cluster-bootstrap upper bound (SPF near the limit, 12.7 here, 12.6 there) differs by 0.1
        point, because of the percentile convention: nearest rank here, interpolated there.
      - The recount's Tranco overlap (42,942) is counted on the list, before NXDOMAIN domains are
        removed. 90 of the 321 NXDOMAIN domains are in Tranco's top 100,000, which gives 42,852 here.
    - The recount listed 31 readings of the protocol. Its choices agree with notes 1–12.
    - **Extended to every published number** (section 7.2, 2), on the final file. The recount saw a skeleton of
      the published totals: keys only, no values. On 15 November, with the re-check from a second location
      included (note 17), it filled 3,699 of the 3,724 published values; 3,621 are identical. The 25 it could
      not fill are the checks of September’s own figures, which need September’s per-domain results.
      (A first comparison on 14 November, before the re-check, gave 3,609 identical; the recount then also
      read certificate issuers of sites seen only from the second location from the wrong row, which it
      fixed itself.) The other 78 are:
      - labels and wording (verdict strings, list names, descriptions), and the bootstrap's group count,
        which the recount gives over all groups and the summary over the groups in each measure's
        population (the intervals are identical);
      - test mode (above) and the Tranco overlap (above);
      - check 3, September side: the recount had only September's published percentages and rebuilt the
        counts from them (±3 domains). The summary counts them exactly from September's own results, and
        reproduces every published September figure;
      - three readings of a key:
        - `not_readable.dnssec_state`: 7 here (2 signed zones plus 5 domains whose DS could not be read),
          2 in the recount (signed zones only). Under the unreadable flags both count 7.
        - Sending providers, unrecognised: both count the same domains as unrecognised. The 7,468 SPF
          records with no include at all stay in the denominator here, as for every sending share
          (16.0%). The recount counts them as unrecognised (30.6%) or leaves them out (18.7%).
        - Web providers, n: 77,727 here, 77,732 there. Five domains have a network with an AS number but
          no name, which cannot be attributed to a provider; no published share changes.

      Once both use the same definition, every count matches. **(a)**

17. **Corrections after the two reviews (section 7.3), 15 November 2026.** Found by the academic review;
    none changes a value in the data file except the counter in the second bullet.
    - **Rounding in the text.** The page rounded prose shares from the one-decimal value, so 40.47% became
      40.5 and then 41%. Prose now rounds from k/n: fully configured is 40%, SPF over the limit 2%. Tables
      and data files were not affected.
    - **Unreadable flag for email.** A zone that fails DNSSEC as a whole gets no email checks from the
      scanner and carries no email error code, so the flag counted 230 unreadable domains instead of 231
      (still 0.3%). The flag now counts it. The not-readable counts were already right (227 plus 4 with
      broken DNSSEC on their own zone).
    - **HTTPS second location.** The re-check from a second location (Cologne, Germany, 15 November) is now
      in the summary: 289 of the 1,986 websites that gave the scan server no handshake answered there.
      Only HTTPS totals change. **(c)**

## Final test-retest (section 7.2, 2a), 16 November 2026

18. **Scan against scan; both HTTPS comparisons published.** Run 2 started on 15 November at 09:00 UTC,
    37.6 hours after the main scan, and its retry pass ran 24 hours after it finished. Reading the final
    comparison showed that run 1's HTTPS result includes the answers from the second location (note 17),
    which run 2 did not have. Section 7.2 (2a) repeats the scan "with the same code and list", so the
    test-retest now compares scan with scan and leaves the second location out of both runs. Run 2 against
    the published HTTPS result is reported beside it, so neither number is hidden: HTTPS outcome kappa
    0.974 scan against scan, 0.935 against the published result. Both are above 0.80, so no flag changes,
    and the email and DNSSEC measures are not affected. This choice was made after the preliminary
    comparison had been seen. **(a)**
    - **Exact counts.** The output now also gives the number of identical domains per measure. A share
      that rounds to 100.0% while some domains differ is shown as "over 99.9%"; DNSSEC signed, for
      example, differs for 4 of 79,976 domains.
    - **Sensitivity check 4.** All five headline measures from run 2 are inside the headline's 95%
      interval.
    - **DNSSEC state (found by the recount, 16 November 2026).** The test-retest of the DNSSEC state
      counted unsigned domains as a state of their own. Section 5 defines the state for signed domains
      only ("every signed domain is in exactly one state"), and whether a domain is signed is already
      its own measure. The code now pairs signed domains with a readable state: n 5,389, kappa 0.927
      instead of 79,974 and 0.999. Still well above 0.80, so no flag changes. **(c)**
    - **Recount.** The separate recount then recomputed all 36 check 4 values and all 61
      test-retest values, both comparisons included; every one is identical.

## Outside review, 20 November 2026

19. **Two post-hoc checks and exacter names (after an outside, AI-assisted review of the draft).**
    Nothing here changes a definition, a rule or a registered number; the summary was re-run with the
    same inputs and seed, and every registered value is byte-identical to the 16 November summary.
    - **Sensitivity check 5, RFC 9989 handling of the measured records** (`effectivePolicyRfc9989`, `rfc9989Check`; called "RFC 9989 only" until the reviewer's follow-up: it is not full RFC 9989 processing, with no policy discovery up the DNS tree and no `np=` check). The
      registered rule combines RFC 7489's `pct` with RFC 9989's `t=`, because receivers follow both.
      Check 5 asks what the primary outcome is when a receiver follows RFC 9989 alone: `pct` is ignored
      (RFC 9989 removed it, Appendix A.6), a record without `p=` is read as `p=none` (section 4.10.1:
      none with a valid `rua`, otherwise no DMARC processing; neither is enforced), and `t=y` lowers the
      policy one level (section 4.7). A record with an invalid `sp=` is read the same way (section 4.10.1),
      added after the final check of 20 November pointed it out; the scanner does not check `np=`.
      Result: 30,660 of 55,106 (55.6%) have no enforcing policy, against 31,530 (57.2%) under the
      registered rule: 870 fewer, −1.6 points, outside the headline interval, so a short note sits next
      to the headline. 871 move to enforced: 842 `p=quarantine` records with `pct` 1–99 (partial →
      quarantine) and 29 `p=quarantine; pct=0` (none → quarantine); 1 moves the other way, a
      `p=quarantine` record with an invalid `sp=` (quarantine → none). Three other moves change a class
      but not the outcome: 156 `p=reject` with `pct` 1–99 (quarantine → reject), 23 records without
      `p=` (invalid → none) and 1 `p=quarantine; t=y` with `pct` 1–99 (partial → none). The reviewer's
      own reconciliation (30,688, 55.7%) counted only the 842 and missed the 29.
    - **Check 1's Tranco count.** "42,852 domains" counts the list domains still registered; the
      separate recount counts 42,942 over the whole list (90 of the 321 NXDOMAIN domains are in Tranco).
      The text now says "still registered".
    - **Check 1, disjoint groups** (`listsCheck(…).disjoint`). Beside the registered comparison (CrUX
      domains in Tranco against the headline, nested), the CrUX domains in the Tranco top 100,000
      against the CrUX domains not in it, as two disjoint groups with a Newcombe interval.
    - **Names.** The primary outcome is now called "no enforcing DMARC policy" (was "not protected
      against spoofing") and the combined measure "valid SPF and enforced DMARC" (was "fully
      configured"), because the study classifies DNS policies and does not measure delivery or DKIM.
      The data keys (`not_protected`, `fully_configured`) are unchanged, so files stay comparable.
      Headline sentence, in two lengths (`headlineFull`, `headlineShort`).
    - **Text.** The Wilson intervals are described as sampling uncertainty only; "similar" is now "no
      difference by our rule"; check 2 says "domain group", not "organisation", and how the
      representative is chosen; the SPF count is described as the scanner's own rule (every DNS-querying
      term in every branch, including terms after an `all` and macro includes counted once), which can
      differ from what a receiver evaluates for one message; the MX criterion is stated (every host `localhost` or
      a name without a dot), with implicit MX as a limitation; the registration time (OSF,
      13 November 2026 23:16:30 UTC) is in the abstract; the September interval says it ignores the
      pairing; Figure 1 has its own CSV; related work adds Kondo et al. (TMA 2025) and the JRC 2025
      uptake report; RFC section numbers where a rule depends on one.
    - Known-answer tests for the RFC 9989 rule are in `analysis.test.mjs`.

## Not in the analysis code for study 1

These are study 2 items, or manual steps. None is needed for study 1:

- the country × sector split (Wikidata mapping, section 4);
- a script that compares each country band with the global band (RQ6). The difference and
  decision-rule functions it needs exist;
- E1 and E3: functions only, to be wired up for study 2;
- the registries' zone-wide DNSSEC figures, which are cited by hand;
- the hand check (section 7.2, 1), which is run separately (notes 13–15).
