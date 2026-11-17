# SOC Investigations

Junior SOC analyst in training. Practice write-ups on alert triage, phishing analysis and log analysis.

## How cases are documented
Every case follows the same structure: [TEMPLATE.md](TEMPLATE.md).
The workflow is always: **alert → hypothesis → evidence → verdict → escalation decision**.
<!-- METHODOLOGY link pending -->

```
investigations/
└── NNN-<type>-<short-slug>/
    ├── README.md     # the write-up
    ├── iocs.csv      # defanged IOCs: type,value,context
    └── img/          # evidence screenshots (NNN-<name>)
```

## Cases
| # | Title | Type | Platform | ATT&CK | Verdict | Link |
|---|---|---|---|---|---|---|
| 001 | SOC257 · VPN connection from an unauthorized country | Unauthorized access | LetsDefend | T1078, T1621, T1110 | True positive · Escalated | [read](investigations/001-unauthorized-access-vpn-foreign-login/) |
| 002 | SOC153 · Suspicious PowerShell script with a download cradle | Malware | LetsDefend | T1204.002, T1059.001, T1059.003, T1105, T1071.001 | True positive · Escalated | [read](investigations/002-malware-powershell-download-cradle/) |

## Tools
Listed as they are used in published cases.
- LetsDefend SOC simulator: Log Management, Email Security, Threat Intel, endpoint data (browser history, process logs, PowerShell script block logging)
- VirusTotal, Cisco Talos, MalwareBazaar: URL and file hash reputation
- AbuseIPDB: IP reputation

## Disclaimer
- All cases use simulated data from free training platforms (TryHackMe SOC Simulator, LetsDefend, CyberDefenders, Blue Team Labs Online).
- No real organization, user or incident is involved. These are practice exercises, not work experience.
- Indicators of compromise are defanged (`hxxp://`, `example[.]com`).
- No solutions to active challenges are published. Write-ups are published only where the platform allows it (for example, CyberDefenders allows write-ups of retired labs only).
- Platform screenshots belong to their respective platforms.

## License
Write-up text: MIT. See [LICENSE](LICENSE).
