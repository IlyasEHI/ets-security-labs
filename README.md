# ets-security-labs

Write-ups of security labs I did during an exchange semester at ÉTS (Montréal), winter 2026. Each lab is in its own folder, with an English and a French version. The focus is the technical analysis: how things work, how I got to the result, and what a defender should take away. Course-definition questions are left out.

Labs were done in teams of 4. The write-ups and the reformulation are by Ilyas El Houdaigui. No teammate names or student IDs appear in this repository.

## Labs

| Lab | Topic | Write-up |
|-----|-------|----------|
| 1 | Malware analysis (process injection, mass-mailer worm, web droppers, string/crypto triage) | [lab1-malware-analysis](lab1-malware-analysis/README.md) |
| 2 | WebGoat web exploitation (SQL injection, path traversal, XXE, XSS, broken auth, client-side controls) | [lab2-webgoat](lab2-webgoat/README.md) |

More labs will be added here.

## Layout

```
ets-security-labs/
  README.md                     this index
  lab1-malware-analysis/
    README.md                   English write-up
    README.fr.md                French write-up
    img/                         screenshots of the analysis steps
  lab2-webgoat/
    README.md
    README.fr.md
    img/
```

## Scope and ethics

These write-ups document analysis only. No repository here contains runnable malware, complete payloads, or live command-and-control infrastructure. All samples were provided in a controlled university lab for defensive study. The code excerpts are short and exist to document a technique, not to reproduce a working tool.
