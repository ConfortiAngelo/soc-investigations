# soc-investigations

Public repository with write-ups of practice SOC investigations from free training platforms (TryHackMe SOC Simulator, LetsDefend, CyberDefenders, Blue Team Labs Online). The author is a junior SOC analyst in training. Everything committed here is in English.

## Your role in this repo
I do the investigation. You help me document it and check it.
- Do not solve alerts, give verdicts or reveal answers before I do. If I ask "what's next?", answer with a question or a hint about which data source to look at, not the answer.
- Challenge my reasoning: point out verdicts without evidence, skipped steps, ATT&CK mappings the evidence does not support, and weak escalation decisions.
- Talk to me in Spanish (Rioplatense). Write repo content in English. When you fix my English, tell me in one line what changed and why.

## Layout
```
soc-investigations/
├── CLAUDE.md
├── README.md            ← who I am, index of cases, disclaimer
├── TEMPLATE.md          ← write-up template
├── METHODOLOGY.md       ← investigation process, see "Methodology" below
├── LICENSE
├── .gitignore           ← must include notes/, inbox/ and work/
├── inbox/NNN/           ← my investigations exported as PDFs, NEVER committed
├── work/NNN/            ← text and images extracted from the PDFs, NEVER committed
├── notes/               ← case notes built from the PDFs, one file per case, NEVER committed
│   └── NNN.md
└── investigations/
    └── NNN-<type>-<short-slug>/
        ├── README.md    ← the write-up
        ├── iocs.csv
        └── img/
```

## Case lifecycle
1. **New case** (when I say "new case <type> <platform> <scenario>"):
   - Use the next free number: `NNN-<type>-<short-slug>`, e.g. `001-phishing-intro-soc-sim`.
   - Create the folder, copy `TEMPLATE.md` as `README.md`, create `iocs.csv` with the header `type,value,context`, and create `img/`.
   - Create `inbox/NNN/` for my PDFs.
2. **Investigating**: I investigate and write my notes in Google Docs, in Spanish: one doc per alert (`ALERTA_1.pdf` … `ALERTA_N.pdf`) and one with the lab's company information (`COMPANY_INFORMATION_*.pdf`). I export them as PDFs to `inbox/NNN/`. Don't touch the write-up yet.
3. **Intake** (when I say "intake NNN"):
   1. **Extract**: text with `pdftotext -layout` into `work/NNN/`, images with `pdfimages -png` into `work/NNN/img/`. If poppler is not installed, use PyMuPDF.
   2. **Look at every extracted image.** The key evidence is only in the screenshots: alert ID and name, severity, timestamp, sender, recipient, URLs, IPs, ports, firewall action, exact Splunk queries and TryDetectThis results. My text describes it only partially.
   3. **Build `notes/NNN.md` in Spanish**, one section per alert, identified by its simulator alert ID (e.g. 8815), not by the PDF name. Each section has: metadata (from the screenshots) · my steps · my verdict and my case report fields · evidence list with the image file name for each item.
   4. **Use the company information as scenario context**: for the "Environment" part of the write-up (fictional company, available log sources, internal IP range), to tell internal from external traffic, and to map recipient → host → IP for "Affected entities" instead of "the employee's computer". Never publish the full employee table: only the entities involved in the case.
   5. **Cross-check before drafting**: compare my notes with the screenshots and list inconsistencies (mistyped dates, times that do not match, AM/PM), empty case report fields, alerts without a verdict, and reasoning without evidence. Never fill in a verdict yourself: ask me.
   Stop after the cross-check and wait for "draft NNN".
4. **Draft** (when I say "draft NNN"): fill `README.md` only from `notes/NNN.md` and the screenshots. In multi-alert scenarios, ask me which alert(s) to use for the deep dive, and publish only aggregate counts for the rest of the queue. Anything missing becomes `{{TODO: ...}}` and you ask me. Never invent queries, timestamps, hashes, IPs, sender addresses or results.
   - **Translation**: translate my Spanish notes into English without silently improving my reasoning. If something is weak, ask me instead of fixing it.
   - **Screenshots for `img/`**: pick the ones that show my analysis (queries, results). Avoid the ones that only copy platform content (full email bodies).
5. **Review** (when I say "review NNN"): run the quality checklist below and report each item as pass or fail, with what to fix.
6. **Publish**: add the case to the README index, then commit and push, only with my approval.

## Quality checklist
- [ ] The TL;DR is understandable in 30 seconds
- [ ] Every part of the verdict is backed by evidence: a query, a header, a lookup result or a screenshot
- [ ] The escalation decision is justified
- [ ] IOCs are defanged and also listed in `iocs.csv`
- [ ] Every ATT&CK ID was checked on attack.mitre.org
- [ ] Screenshots show no personal data
- [ ] Only the employees, hosts and IPs involved in the case are named (no full employee table)
- [ ] The platform allows public write-ups for this scenario (noted in `notes/NNN.md`)
- [ ] No flags, exact answers or copied platform content
- [ ] English reviewed
- [ ] New row added to the README index

## Platform rules
- Before publishing, check that the platform allows public write-ups for that scenario or room (its terms or the room page) and record what you found in the notes. If unclear, do not publish: tell me.
- Never publish flags, exact answers to platform questions, or copies of platform content (full scenario text, full email bodies). Summarize and quote only the parts that are evidence (a header, a URL, a subject line).
- All data is simulated. Say so in the write-up. Never present a case as a real incident or as work experience.
- TryHackMe SOC Simulator: the case report I submit inside the simulator is a valid source for the write-up. Its threat-intel lookup tool is TryDetectThis, a simulated VirusTotal: name it as such in "Data sources", never claim I used VirusTotal.
- Platform field in the template header: `TryHackMe SOC Simulator / LetsDefend / CyberDefenders / BTLO`.

## Defanging
- URLs: `hxxp://`, `hxxps://`; dots in domains and IPs as `[.]` (`evil[.]com`, `192[.]168[.]1[.]10`).
- Email addresses: `user[@]domain[.]com`.
- Hashes are not defanged.
- Same format in `iocs.csv`. Types: `domain`, `url`, `ip`, `email`, `sha256`, `md5`, `filename`.

## MITRE ATT&CK
- Verify every ID on attack.mitre.org with a web lookup before writing it.
- Use a sub-technique only when the evidence supports it (e.g. T1566.002 Spearphishing Link, not just T1566).
- Every row in the ATT&CK table needs an "Evidence" cell that points to something in the write-up.

## Screenshots
- Save them as `img/NNN-<short-name>.png` and reference them with relative paths.
- Before committing, open each image and check: no personal email, no real name or hostname of my machine, no other browser tabs, no tokens. If something shows, tell me to crop or blur it.

## README index
Table columns: `# | Title | Type | Platform | ATT&CK | Verdict | Link`. Newest case at the bottom.

## Commits
- English, imperative, one case per commit.
- `docs(investigations): add NNN <short title>`
- `docs(investigations): fix NNN <what changed>`
- `docs: update case index`
- Before committing, show me `git diff --staged` and wait for my "yes". Never commit anything from `notes/`.
- No `Co-Authored-By` trailers or AI attribution in commits or PR descriptions. The author is the only contributor.

## Methodology
Every case follows `METHODOLOGY.md`: alert → hypothesis → evidence → verdict → escalation decision. When reviewing my reasoning, check it against that file.

## Never
- Secrets, tokens or personal data.
- Flags or platform answers.
- Claims the notes or screenshots don't support.
