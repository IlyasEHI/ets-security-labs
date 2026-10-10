# ets-security-labs

Write-ups des labos de sécurité que j'ai faits en échange à l'ÉTS (Montréal) à l'hiver 2026. Chacun déroule comment un bug ou un malware fonctionne vraiment, comment j'arrive au résultat, et ce qu'un défenseur doit en faire. C'est le raisonnement qui compte, pas une liste de drapeaux ramassés.

Tout a été fait sur des cibles légales uniquement : applications d'entraînement volontairement vulnérables et échantillons fournis en labo, exécutés en local. Aucun système réel n'a été touché.

English: [README.md](README.md).

## Labos

| Labo | Sujet | Write-up |
|------|-------|----------|
| 1 | Analyse de malware : injection de processus, ver mass-mailer, droppers web, triage strings et crypto | [EN](lab1-malware-analysis/README.md) · [FR](lab1-malware-analysis/README.fr.md) |
| 2 | Exploitation web avec WebGoat : injection SQL, path traversal, XXE, XSS, authentification cassée, contrôles côté client | [EN](lab2-webgoat/README.md) · [FR](lab2-webgoat/README.fr.md) |
| 3 | Test d'intrusion d'un hôte Linux : recon, découverte d'identifiants, injection de commande, et escalade root via UDF MySQL | [EN](lab3-linux-pentest/README.md) · [FR](lab3-linux-pentest/README.fr.md) |

D'autres s'ajouteront au fur et à mesure.

## Ce que donne chaque write-up

- Le chemin technique complet, étape par étape, avec les vraies charges utiles ou le vrai code.
- Un correctif court pour chaque faille, côté défense.
- Pour les malwares, une attribution de famille probable avec les indices qui la soutiennent, jamais présentée comme plus certaine que ce que les preuves permettent.
- Une référence CWE ou MITRE ATT&CK quand elle colle, et rien de forcé quand elle ne colle pas.
- Une version anglaise et une version française pour chaque labo.

## Organisation

```
ets-security-labs/
  README.md            cet index (anglais)
  README.fr.md         cet index (français)
  lab1-malware-analysis/
    README.md          write-up anglais
    README.fr.md       write-up français
    img/               captures des étapes d'analyse
  lab2-webgoat/
    README.md
    README.fr.md
    img/
  lab3-linux-pentest/
    README.md
    README.fr.md
    img/
```

## Outils utilisés dans les labos

Burp Suite, CyberChef, JS-Beautify, l'utilitaire `strings`, un décodeur JJEncode, les devtools du navigateur, et une instance WebGoat locale. Chaque write-up précise quel outil a servi à quoi.

## Périmètre et éthique

Ce sont des write-ups d'analyse et d'exploitation contre des cibles que j'avais le droit de tester : les applications volontairement vulnérables d'OWASP et des échantillons de malware distribués dans un labo universitaire contrôlé, le tout exécuté en local. Aucun dépôt ici ne livre de malware exécutable, de charge utile complète ou d'infrastructure de command and control active. Les extraits de code sont courts et servent à expliquer une technique, pour pouvoir la détecter et l'empêcher.

## À propos

Je suis étudiant ingénieur en cybersécurité, en route vers un poste en test d'intrusion. Ces labos sont là où je m'entraîne à lire du code offensif et à casser des applications web volontairement, puis à écrire ce que j'ai trouvé pour pouvoir défendre chaque étape à l'oral.
