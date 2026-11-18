# [ID] Short title (e.g. Phishing with credential-harvesting link)
Platform: TryHackMe SOC Simulator / LetsDefend / CyberDefenders / BTLO · Date: YYYY-MM-DD · Difficulty: Easy
Verdict: True positive / False positive · Escalated: Yes / No
Data: simulated training environment. No real organization or user data involved.

## TL;DR
Three lines: what happened, the verdict, the action taken.

## 1. Alert
What fired, severity, source (SIEM / EDR / email gateway).
Multi-alert scenarios: queue summary (total alerts, true/false positives, common patterns). Sections 2-9 focus on the most representative alert(s).

## 2. Hypothesis
What could this be? What would confirm or rule it out?

## 3. Environment and data sources
Environment: the (fictional) organization, its internal IP range and which log sources exist (and which don't, e.g. no EDR).
Data sources: logs, mail headers, PCAP, EDR telemetry, threat intel used.

## 4. Investigation
Step by step: queries run (SPL / KQL / filters), tools used, what each result showed.
Screenshots in ./img (no personal data).

## 5. Findings and verdict
True positive / false positive, and why. Timeline of events.
Affected entities: user → host → IP, only those involved.

## 6. Escalation decision
Close or escalate to L2, and why.

## 7. IOCs (defanged, also in iocs.csv)
| Type | Value | Context |

## 8. MITRE ATT&CK
| Tactic | Technique | Evidence |

## 9. Response and recommendations
Containment, eradication, what detection should be tuned.

## 10. What I learned
