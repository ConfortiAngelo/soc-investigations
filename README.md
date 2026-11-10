# SOC Investigations

Alert triage and incident write-ups from SOC training platforms (LetsDefend, CyberDefenders, Blue Team Labs Online). Each case follows the same analyst workflow: **alert → hypothesis → evidence → verdict → IOCs → ATT&CK → response**.

## Investigations

| Case | Platform | Type | Verdict | ATT&CK | Write-up |
|---|---|---|---|---|---|
| SOC153 · Suspicious PowerShell script executed | LetsDefend | Malware / execution | TP · High | T1204.002, T1059.001, T1059.003, T1105, T1071.001 | [read](investigations/letsdefend/SOC153-suspicious-powershell-script/) |
| SOC257 · VPN connection from unauthorized country | LetsDefend | Identity / unauthorized access | TP · Medium | T1078, T1621, T1110 | [read](investigations/letsdefend/SOC257-vpn-unauthorized-country/) |

## How each case is written

[`TEMPLATE.md`](TEMPLATE.md) is the structure every write-up uses, including a publishing checklist:

1. **Alert:** the raw alert fields as received.
2. **Hypothesis:** benign vs. malicious explanations, and the evidence that would separate them.
3. **Investigation:** one section per data source (logs, EDR, email, proxy, threat intel), with screenshots.
4. **Findings and verdict:** True/False Positive plus a timeline.
5. **IOCs:** defanged, with where each one came from.
6. **MITRE ATT&CK:** tactic · technique · the evidence that proves it.
7. **Response and recommendations.**
8. **What I learned.**

## Repository layout

```
investigations/
└── <platform>/
    └── <rule-or-lab-id>-<short-name>/
        ├── README.md     # the write-up
        └── img/          # evidence screenshots
```

## Publishing rules

Write-ups are published only where the platform allows it (for example, CyberDefenders allows write-ups of **retired** labs only, linking back to cyberdefenders.org). They show reasoning and evidence, not answer lists.

## License

Write-up text: [MIT](LICENSE). Platform screenshots belong to their respective platforms.
