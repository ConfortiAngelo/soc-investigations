# Investigation methodology

How I triage and investigate every alert in this repository. [TEMPLATE.md](TEMPLATE.md) is the output format; this file is the process behind it.

The workflow is always: **alert → hypothesis → evidence → verdict → escalation decision**.

## 1. Read the alert
- Read every field before pivoting to external tools: rule, time, host, user, source → destination, file name, hash, URL.
- Write down what the security control did. *Detected* is not *blocked*.
- Note the initial severity. The final severity can change after the investigation.

## 2. Write the hypothesis
- Write one benign and one malicious explanation for the alert.
- For each one, list the evidence that would confirm it or rule it out.
- The investigation is the search for that evidence, not for a verdict I already chose.

## 3. Collect evidence
For every data source, record three things: the query or filter used, what it showed (with a screenshot) and what it means for the hypothesis.

Where to look first, by alert type:

| Alert type | Check first |
|---|---|
| Phishing / email | Sender and Return-Path, Reply-To, SPF / DKIM / DMARC results, sender domain, URLs and attachments, who else received it, whether anyone clicked or replied |
| Endpoint / malware | Process tree and parent process, command line, script block logs, network connections, file hash, persistence |
| Authentication / access | Source IP history and location, failed vs successful logins, MFA events, user-agent and protocol details |

Rules:
- **Correlate at least two sources.** One log alone can look normal; the pattern shows up when sources are put side by side.
- **Threat intel is context, not a verdict.** Read both the detection count and the context (age of reports, confidence, tags). Name the exact tool used. In TryHackMe SOC Simulator the lookup tool is TryDetectThis, a simulated VirusTotal.
- **No evidence, no claim.** If a step could not be done (for example, no sandbox), write that down instead of guessing.

## 4. Decide the verdict
- **True positive** or **false positive**, and why, in one or two sentences.
- Every part of the verdict points to evidence: a query, a header, a lookup result or a screenshot.
- Build a timeline of events.
- Check impact: did the attack succeed, was it blocked, is any account or host compromised? Blocked does not mean closed.

## 5. Make the escalation decision
Escalate to L2 when any of these is true:
- Malicious code ran, or a host may be compromised.
- Valid credentials were used or leaked, even if the login was blocked.
- Confirming the scope needs tools or access an L1 analyst does not have (sandbox, forensics, other hosts).
- More than one user or host is affected.

Close at L1 when the alert is a false positive with evidence, or a true positive that was fully blocked with no compromised user, account or host.

Write the reason in one or two sentences. Contain first when the risk is active (isolate the host, block the IP), then escalate with the evidence collected.

## 6. Document IOCs and ATT&CK
- Defang every IOC: `hxxp://`, `hxxps://`, `evil[.]com`, `192[.]168[.]1[.]10`, `user[@]domain[.]com`. Hashes are not defanged.
- List the same IOCs in `iocs.csv` (`type,value,context`).
- Verify every ATT&CK ID on attack.mitre.org before writing it. Use a sub-technique only when the evidence supports it.
- Every ATT&CK row has an *Evidence* cell that points to something in the write-up.

## 7. Response and recommendations
- **Containment:** what stops the activity now.
- **Eradication and recovery:** what removes it and restores normal state.
- **Detection:** what rule or threshold would catch it earlier next time.

## 8. Multi-alert scenarios
Some scenarios (for example, TryHackMe SOC Simulator) generate a queue of 20 to 30 alerts instead of one.
- Triage the queue by severity first, then by time.
- Group alerts that share a pattern: same sender, domain, subject, URL or attachment.
- Keep one line per alert in private notes: ID, what it was, verdict, key evidence.
- The write-up publishes the queue summary (totals, true and false positives, common patterns) and a deep dive on the most representative alert(s). It does not publish a verdict for every alert.

## 9. Before publishing
- The platform allows public write-ups for that scenario or lab.
- No flags, exact answers or copied platform content.
- Screenshots show no personal data.
- The case is presented as a simulated training exercise, never as a real incident or work experience.
