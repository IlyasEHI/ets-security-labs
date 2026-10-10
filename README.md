# ets-security-labs

Write-ups from the security labs I did on exchange at ÉTS (Montréal) in winter 2026. Each one walks through how a bug or a piece of malware actually works, how I got to the result, and what a defender should do about it. The reasoning is the point, not a list of flags captured.

Everything was done on legal targets only: deliberately vulnerable training apps and lab-provided samples, run locally. No real systems were touched.

Français : [README.fr.md](README.fr.md).

## Labs

| Lab | Topic | Write-up |
|-----|-------|----------|
| 1 | Malware analysis: process injection, mass-mailer worm, web droppers, string and crypto triage | [EN](lab1-malware-analysis/README.md) · [FR](lab1-malware-analysis/README.fr.md) |
| 2 | WebGoat web exploitation: SQL injection, path traversal, XXE, XSS, broken authentication, client-side controls | [EN](lab2-webgoat/README.md) · [FR](lab2-webgoat/README.fr.md) |
| 3 | Linux host penetration test: recon, credential discovery, command injection, and a MySQL UDF escalation to root | [EN](lab3-linux-pentest/README.md) · [FR](lab3-linux-pentest/README.fr.md) |

More will be added as I finish them.

## What each write-up gives you

- The full technical path, step by step, with the real payloads or code.
- A short fix for each issue, from the defender's side.
- For malware, a probable family attribution with the indicators it rests on, never stated as more certain than the evidence allows.
- A CWE or MITRE ATT&CK reference where it fits, and nothing forced where it does not.
- An English and a French version of every lab.

## Layout

```
ets-security-labs/
  README.md            this index (English)
  README.fr.md         this index (French)
  lab1-malware-analysis/
    README.md          English write-up
    README.fr.md       French write-up
    img/               screenshots of the analysis steps
  lab2-webgoat/
    README.md
    README.fr.md
    img/
  lab3-linux-pentest/
    README.md
    README.fr.md
    img/
```

## Tools I used across the labs

Burp Suite, CyberChef, JS-Beautify, the `strings` utility, a JJEncode decoder, browser devtools, and a local WebGoat instance. Each write-up says which tool did what.

## Scope and ethics

These are analysis and exploitation write-ups against targets I was allowed to test: OWASP's deliberately vulnerable apps and malware samples handed out in a controlled university lab, all run locally. No repository here ships runnable malware, complete payloads, or live command-and-control infrastructure. The code excerpts are short and exist to explain a technique so it can be detected and prevented.

## About

I am a cybersecurity engineering student working toward a role in penetration testing. These labs are where I practice reading offensive code and breaking web applications on purpose, then writing up what I found so I can defend each step out loud.
