# [ID] Short title

Platform · Alert date · Investigated: Month YYYY · Difficulty / Level

**Verdict: TP / FP / Benign TP** · Final severity: … (alert: …) · Escalated: yes/no

## 1. Alert

Screenshot (`img/alert.jpeg`) and the key fields: rule, time, host/user, source → destination, file/hash, EDR action.

## 2. Hypothesis

What benign explanation and what malicious explanation fit the alert? What evidence would confirm each one?

## 3. Investigation

For each source (SIEM / log management, EDR, email security, proxy, threat intel), write:
- the query or filter used,
- what it showed (screenshot in `./img`),
- what it means for the hypothesis.

```spl
index=... sourcetype=... src_ip=...
```

## 4. Findings and verdict

TP or FP, and why in one or two sentences.

| Time | Event |
|---|---|
| | |

## 5. IOCs

Defang everything (`hxxps://`, `example[.]com`, `1.2.3[.]4`).

| Type | Value | Source |
|---|---|---|
| | | |

## 6. MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| | Txxxx Name | what in the logs proves it |

## 7. Response and recommendations

Actions taken (containment, eradication, recovery) and recommendations to prevent or detect it earlier.

## 8. What I learned

2-4 bullets. What would you do faster or differently next time?

---

### Publishing checklist

- [ ] The platform allows public write-ups for this content (CyberDefenders: **retired labs only**, with a link to cyberdefenders.org).
- [ ] No flags or answer lists: the write-up shows reasoning and evidence.
- [ ] IOCs defanged; no real personal data.
- [ ] Every claim is backed by a screenshot, log line or query in this folder.
