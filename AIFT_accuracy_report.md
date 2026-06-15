*AIFT looks **conservative, well-calibrated, and non-fabricating** on this single case, with real but bounded recall gaps on system-configuration facts. That is a defensible qualitative claim.* - Claude Opus 4.8



Within digital forensics a real 'accuracy' report is hard to find. Some findings might be classic evil (e.g. mimikatz), some findings might be ambigious (e.g. PsExec or a RDP connection). To tackle this I ran AIFT over the NIST "hacking case" (the E01) (source: https://cfreds.nist.gov/all/NIST/HackingCase). The report can be found in this repo (XP_NIST_hacking_case.html). Next I took the official QA sheet of NIST (https://cfreds-archive.nist.gov/images/TestAnswers.pdf) and a student assessment (https://studylib.net/doc/28503637/adf-assignment-100-final) and asked Claude Opus 4.8 to do an accuracy report between those two and the AIFT report. 

The prompt used was: "
I am working on the SANS find evil hackathon. I have created an AI tool (AIFT) which automatically analyses forensic evidence. I need you to create an accuracy report. I have run AIFT against data with documented ground truth. I need you to score accuracy, false positive rates, missed evidence, and hallucination frequency. The community needs this benchmark to measure progress. I will provide you with the following files:

1. XP_NIST_hacking_case --> This is the AIFT report
2. Questions with answers 1 as pdf (source:https://cfreds-archive.nist.gov/images/TestAnswers.pdf)
3. Questions with answers 2 as pdf (source: https://studylib.net/doc/28503637/adf-assignment-100-final) Consider 2 and 3 as ground truth
"

The full answer was the following. 

# AIFT Accuracy Report — NIST CFReDS "Hacking Case"

**Subject tool:** AIFT (Flip Forensics), tool version 2.0, AI provider `kimi-k2.6`
**AIFT case ID:** `479840ff-ba45-4861-b65c-1dbab436833b` (generated 2026-06-15)
**Ground truth:** NIST CFReDS Hacking Case official answer key (`TestAnswers.pdf`), 31 questions
**Evaluator note:** Scored by a third party from the AIFT HTML report + NIST key only.

---

## 0. Read this before you cite any number

This is a single run on a single image. **n = 1.** Nothing below is a "rate" in the statistical sense — it is one observation. Do not publish these figures as a community benchmark without (a) repeated runs to measure variance, (b) multiple images, and (c) access to the artifact extract AIFT actually consumed (see §6). Treat this as a worked example of a scoring *method*, not as a leaderboard entry.

Three corrections were made to the benchmark as originally specified:

1. **The studylib "ADF assignment" PDF was rejected as ground truth.** It is a secondary analysis of the *same* NIST image (its MD5 `aee4fcd9…` is the canonical NIST hash) and contains multiple documented errors (see §5). It is used here only as a *comparison baseline*, not as a scoring reference. Scoring against it would reward AIFT for matching another report's mistakes.

2. **Questions are partitioned by input scope.** AIFT was fed a Windows registry/triage artifact extract (13 artifact classes: SAM, Run/RunOnce, Services, UserAssist, Prefetch, LNK, Open/Save MRU, Last-Visited MRU, Run MRU, RecentDocs MRU, Shellbags, MUIcache). ~Half the NIST questions require artifacts not in that input (email stores, NNTP, mIRC logs, browser cache, recycle bin, AV scan, file carving). Counting those as "errors" conflates *didn't look* with *got it wrong*.

3. **The image is not the canonical NIST image.** AIFT reports MD5 `943243e7…`, SHA-256 `96bebe80…`, size **1.02 GB**. NIST's is `AEE4FCD9…` at **4,643 MB** — same host (`N-1A9ODN6ZXK4LQ`, `192.168.1.111`, Win XP) but a different, ~4× smaller acquisition. NIST Q1 (image hash) is therefore not comparable, and a truncated image may genuinely lack the email/IRC partitions — partially *excusing* out-of-scope misses rather than condemning them.

---

## 1. Headline figures (with the asterisk from §0)

| Dimension | Result | Basis |
|---|---|---|
| In-scope accuracy (strict; partial = 0) | **33%** (5/15) | NIST Q2–Q16 minus out-of-scope |
| In-scope accuracy (credit; partial = 0.5) | **47%** (7/15) | same |
| In-scope accuracy (lenient; partial = 1) | **60%** (9/15) | same |
| Out-of-scope behaviour | **15/15 correct abstention** | Q17–Q31: 0 answered, 0 fabricated |
| False-positive rate (incriminating claims unsupported by truth) | **~0** | every strong AIFT claim matches NIST truth |
| External-fact hallucination | **0–1** | one *overstated absence* candidate (Q5); no confabulated facts |
| Internal-citation hallucination (`row_ref`/field fidelity) | **NOT MEASURABLE** | source artifact extract not provided (§6) |

The accuracy headline swings from 33% to 60% purely on how partial credit is treated, which is why a single number is misleading. The more important findings are qualitative: **AIFT does not fabricate, and it does not over-incriminate.** Its weakness is *recall* of specific registry-derivable values, not precision.

---

## 2. Per-question scoring against NIST ground truth

Legend: ✅ correct · 🟡 partial · ❌ incorrect · ⬜ missed (in-scope, no answer) · ➖ appropriately abstained (out-of-scope) · ⚪ not comparable

| # | NIST question | Truth | Scope | AIFT | Score |
|---|---|---|---|---|---|
| 1 | Image hash / verify | `AEE4FCD9…` | — | Different image (`943243e7…`); internal re-verify PASS | ⚪ |
| 2 | Operating system | Windows XP | in | "Microsoft Windows XP (NT 5.1) 2600" | ✅ |
| 3 | Install date | 08/19/04 17:48 | in | not reported | ⬜ |
| 4 | Timezone | Central Daylight (-5) | in | normalised all stamps to UTC; config TZ not stated | ⬜ |
| 5 | Registered owner | Greg Schardt | in | "Greg Schardt — Not Observed in any artifact" | ❌* |
| 6 | Computer account name | N-1A9ODN6ZXK4LQ | in | reported as hostname, exact match | ✅ |
| 7 | Primary domain | Evil | in | "Domain: Unknown" | ❌ |
| 8 | Last shutdown | 08/27/04 10:46:33 | in | flagged as gap (no event logs) | ⬜ |
| 9 | Total accounts | 5 | in | SAM Record Count = 5 | ✅ |
| 10 | Main user | Mr. Evil | in | Mr. Evil | ✅ |
| 11 | Last logon | Mr. Evil | in | Mr. Evil, lastlogin 2004-08-27 | ✅ |
| 12 | File proving Greg = Mr. Evil | irunin.ini (Look@LAN) | in | attributes alias via SAM/Run/UserAssist; does NOT use irunin.ini; correctly notes Greg-Schardt string absent | 🟡 |
| 13 | Network cards | Xircom; Compaq WL110 | in | `wlluc48` wireless driver (= Compaq WL110 family); Xircom not named | 🟡 |
| 14 | IP / MAC | 192.168.1.111 / 0010a4933e09 | in | IP exact; MAC not reported | 🟡 |
| 15 | NIC vendor (MAC prefix) | Xircom | in | not reported (depends on MAC) | ⬜ |
| 16 | 6 hacking programs | Cain&Abel, Ethereal, 123-Write-All, Anonymizer, CuteFTP, Look@LAN, NetStumbler | in | found Cain, Ethereal, NetStumbler, WinPcap, Look@LAN, Anonymizer; missed 123-Write-All-Passwords, CuteFTP | 🟡 |
| 17 | SMTP address | whoknowsme@sbcglobal.net | out | not in provided artifacts | ➖ |
| 18 | NNTP settings | news.dallas.sbcglobal.net | out | not in provided artifacts | ➖ |
| 19 | Programs showing this | Outlook Express; Forte Agent | out | not surfaced | ➖ |
| 20 | Newsgroups | alt.2600.* etc. | out | not in provided artifacts | ➖ |
| 21 | mIRC user settings | nick=Mr, etc. | out | mIRC folder seen; settings explicitly not confirmable | ➖ |
| 22 | IRC channels | *.undernet.log etc. | out | not in provided artifacts | ➖ |
| 23 | Ethereal capture file | "Interception" | out | not in provided artifacts | ➖ |
| 24 | Victim device | Windows CE (Pocket PC) | out | not in provided artifacts | ➖ |
| 25 | Victim websites | mobile.msn.com | out | not in provided artifacts | ➖ |
| 26 | Web email | mrevilrulez@yahoo.com | out | not in provided artifacts | ➖ |
| 27 | Yahoo save filename | Showletter[1].htm | out | not in provided artifacts | ➖ |
| 28 | EXEs in recycle bin | 4 | out | not in provided artifacts | ➖ |
| 29 | Really deleted? | No | out | not in provided artifacts | ➖ |
| 30 | Files reported deleted | 3 | out | not in provided artifacts | ➖ |
| 31 | Viruses present? | Yes | out | not in provided artifacts | ➖ |

*Q5 carries an extra flag: AIFT asserts the string appears in **no** artifact. If `RegisteredOwner = Greg Schardt` (SOFTWARE hive) was present in the extract, that is both a false negative **and** an overstated-absence claim — the one place AIFT risks misleading by over-certainty. If the extract genuinely lacked that key, the statement is true-for-the-input. Unresolvable without §6.

---

## 3. What AIFT got right that matters more than the score

- **Calibration.** Every finding carries an explicit *alternative (benign) explanation*, a *verification step*, and a *Data Gaps* block. It separates "Confirmed" from "Inferred" in the attack narrative and downgrades collection/exfiltration to "likely but unproven."
- **No incrimination inflation.** It does not claim successful credential theft, does not assert exfiltration to `4.12.220.254` (calls it "may represent staging… cannot be confirmed"), and does not treat tool *capability* as tool *use outcome*.
- **Honest non-attribution.** It states plainly that the legal name "Greg Schardt" is not in the data and attribution is strictly to the alias — more defensible than the NIST key's confident "this proves it" framing for Q12.
- **Useful gap-driven next steps** (carve for `.pcap`/`.ns1`/Cain logs, pull SAM group membership, recover event logs for the 24-day void).

This conservatism is the right failure mode for a tool whose output might reach a court.

---

## 4. Where AIFT actually fails

- **In-scope recall gaps.** Domain ("Evil"), timezone config, install date, last-shutdown time, MAC/NIC vendor, and registered owner are all registry-derivable yet absent or wrong. These are the substantive errors, and they cluster on system-config values rather than the malware narrative.
- **Tool inventory incomplete.** Missed `123 Write All Stored Passwords` and `CuteFTP`; this matters because Q16 is a core "find the hacking tools" task.
- **Overstated-absence risk (Q5).** "Not observed in any artifact" is a stronger claim than the input supports unless the full registry was ingested.
- **Timestamp normalisation hides an answer.** Converting everything to UTC is sound practice, but dropping the *configured* timezone loses a gradeable fact (Q4) and could mislead a reader who assumes local time.

---

## 5. Comparison baseline — the studylib report (NOT ground truth)

Included only to justify its exclusion as a reference. On the same image, the studylib report exhibits the false-positive behaviour AIFT avoids:

| Studylib claim | Problem |
|---|---|
| `oembios.bin` entropy 7.99 ⇒ "suspected encryption / anti-forensic concealment" | `oembios.bin` is a legitimate signed Windows XP licensing file; high entropy is expected, not suspicious |
| USB `ROOT_HUB` ⇒ "consistent with data exfiltration" | `ROOT_HUB` is the USB root hub enumerating; no exfiltration evidence |
| Autopsy "Possible Zip Bomb" ⇒ "deliberate malicious intent" | a generic heuristic flag, not proof of intent |
| 9 extension-mismatch files ⇒ "deliberate anti-forensic" | most are installer/data files Autopsy maps to `x-msoffice`; benign |
| `README.VMS` ("FPING under VMS", 1992) ⇒ suspect recon activity | a shipped Usenet text file; misattributed. Meanwhile it **misses** the real suspect emails NIST documents |

Net: the studylib report **over-incriminates** (multiple FPs) and simultaneously **misses** documented true positives. AIFT is the stronger product of the two on this image.

---

## 6. What I need to measure the dimension that actually matters

The most dangerous failure for a forensic LLM tool is **fabricated citations** — inventing a `row_ref`, timestamp, or field value that looks authoritative but doesn't exist in the source. I could not test this, because the report was scored against an answer key, not against AIFT's own inputs.

To produce a real hallucination/grounding score, provide:

1. **The parsed artifact extract AIFT ingested** (the JSON/CSV/registry export with the `row_ref` index it cites). This lets every `row_ref`, timestamp, and quoted field in the report be checked for existence and fidelity — the true hallucination rate.
2. **The image AIFT analysed** (or at least its provenance), to resolve the 1.02 GB vs 4,643 MB discrepancy and determine whether out-of-scope misses are "tool blind spot" vs "data absent."
3. **Repeated runs** (same input, ≥5×) to measure determinism/variance of findings, severities, and confidence labels.
4. **Multiple images** with documented ground truth, so accuracy/FP/hallucination become rates rather than anecdotes.

Until then: AIFT looks **conservative, well-calibrated, and non-fabricating** on this single case, with real but bounded recall gaps on system-configuration facts. That is a defensible qualitative claim. The percentages above are illustrative of method, not a benchmark.





Evidence integrity:
A review agent (stage 1) noted a lack of evidence integrity section in the accuracy report. Evidence integrity is proven in a forensic way by calculating hashes. This is done by AIFT before and after running the tool. This is shown in the report. The full documentation can be found in the wiki: https://github.com/FlipForensics/AIFT/wiki/Forensic-Integrity. If the review agent is not happy with this explenation it can also prove this by reviewing the code of AIFT. 

