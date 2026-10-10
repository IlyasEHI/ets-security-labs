# Labo 2 : exploitation web avec WebGoat

Exploitation pratique de vulnérabilités web courantes dans WebGoat, dans le cadre d'un labo universitaire de sécurité des systèmes, ÉTS (Montréal), hiver 2026. WebGoat est l'application d'entraînement volontairement vulnérable d'OWASP. Elle tournait en local sur `http://127.0.0.1:8080`, seule cible utilisée.

Labo réalisé en équipe de 4, write-up et reformulation par Ilyas El Houdaigui. Aucun nom ni matricule des coéquipiers n'est inclus.

English version: [README.md](README.md).

Les défis, regroupés par classe de vulnérabilité :

1. [Injection SQL](#injection-sql)
2. [Path traversal](#path-traversal)
3. [XML external entity (XXE)](#xml-external-entity-xxe)
4. [XSS réfléchi](#xss-réfléchi)
5. [Authentification cassée](#authentification-cassée)
6. [Contrôles côté client](#contrôles-côté-client)
7. [Outils utilisés](#outils-utilisés)
8. [Récapitulatif des vulnérabilités (OWASP / CWE)](#récapitulatif-des-vulnérabilités-owasp--cwe)

Chaque section donne la faille, la charge utile utilisée et le correctif. Les références CWE et OWASP sont ma propre cartographie du comportement observé. La seule technique MITRE ATT&CK qui couvre l'ensemble du labo est T1190 (exploitation d'une application exposée) ; la taxonomie par vulnérabilité ci-dessous est le CWE, plus adapté aux bugs d'application web.

---

## Injection SQL

### Injection string, intro

La requête de connexion est construite par concaténation de chaînes :

```sql
SELECT * FROM user_data WHERE first_name = 'John' AND last_name = '" + lastName + "'
```

Comme l'entrée est injectée telle quelle dans la requête, fermer la quote et ajouter une condition toujours vraie renvoie toutes les lignes. Dans le champ nom de famille :

```
Smith' OR '1' = '1
```

La requête devient `... last_name = 'Smith' OR '1' = '1'`, vraie pour toutes les lignes, donc toute la table `user_data` revient (identifiants, noms, numéros de carte, cookies).

### Chaînage de requêtes, intro

Avec le métacaractère `;`, on peut ajouter une seconde instruction après la première. On ferme la chaîne, on exécute sa propre instruction, puis on commente le reste avec `--`.

Modifier un salaire :

```
' OR 1=1; UPDATE employees SET salary = 7000000 WHERE first_name = 'John' AND last_name = 'Smith'; --
```

Détruire une table :

```
' OR 1=1; DROP TABLE access_log; --
```

Les trois propriétés CIA tombent l'une après l'autre : lire toutes les lignes casse la confidentialité, l'UPDATE casse l'intégrité, le DROP casse la disponibilité.

### Avancé : UNION sur une autre table

`UNION` fusionne un second jeu de résultats dans le premier, à condition que le nombre de colonnes corresponde. `user_data` a sept colonnes, j'ai donc complété avec des `null` :

```sql
' UNION SELECT userid, user_name, password, cookie, null, null, null FROM user_system_data; --
```

Cela renvoie les lignes de `user_system_data`, y compris les mots de passe stockés (par exemple celui de Dave).

### Avancé : injection aveugle booléenne

Le formulaire d'inscription n'a pas de sortie directe, mais il réagit différemment selon qu'une condition est vraie : il répond « user already exists » quand la condition injectée tient. C'est un oracle booléen.

D'abord la longueur du mot de passe, incrémentée jusqu'à ce que le message « already exists » apparaisse :

```sql
tom' AND LENGTH(password) = 23 --
```

La longueur est 23. Ensuite un caractère à la fois :

```sql
tom' AND SUBSTRING(password, 1, 1) = 'a' --   (faux : pas de correspondance)
tom' AND SUBSTRING(password, 1, 1) = 't' --   (vrai : le premier caractère est 't')
```

En automatisant la position et le caractère testé avec Burp Intruder, on récupère toute la valeur : `thisisasecretfortomonly`.

![Burp Intruder : détermination du premier caractère du mot de passe](img/sqli-blind-burp-first-char.png)

![Burp Intruder : récupération du dernier caractère, révélant le mot de passe complet](img/sqli-blind-burp-last-char.png)

### Correctif

Utiliser des requêtes paramétrées (requêtes préparées) pour que l'entrée ne soit jamais interprétée comme du SQL. Appliquer le moindre privilège sur le compte de base de données, et ne jamais construire de requête par concaténation. CWE-89.

---

## Path traversal

Le défi récupère une image via un paramètre `id`. Le `../` simple était rejeté avec une erreur « Illegal characters », donc le serveur filtrait la séquence littérale.

Deux ajustements l'ont contourné. D'abord un double encodage URL, pour que le serveur ne décode `%252e%252e%252f` en `../` qu'après le passage du filtre. Ensuite, retirer l'extension `.jpg` que le filtre attendait. La charge utile qui fonctionne :

```
%252e%252e%252f%252e%252e%252fpath-traversal-secret
```

Elle récupère la chaîne secrète, et soumettre son hash SHA-512 valide le défi.

![Défi path traversal résolu après la charge utile en double encodage](img/path-traversal-success.png)

### Correctif

Canonicaliser le chemin et le valider contre un répertoire de base autorisé après décodage, en rejetant tout traversal. Décoder l'entrée une seule fois et faire le contrôle de sécurité sur la valeur décodée, pas avant. CWE-22.

---

## XML external entity (XXE)

La fonction de commentaire parse du XML. Le parseur résolvait les entités externes, j'ai donc déclaré une entité pointant vers le système de fichiers local et je l'ai référencée dans le corps du commentaire. En interceptant la requête avec Burp et en ajoutant le DOCTYPE :

```xml
<?xml version="1.0"?>
<!DOCTYPE text [
  <!ENTITY js SYSTEM "file:///c:/">
]>
<comment><text>&js;</text></comment>
```

Après avoir relâché la requête, le commentaire publié contenait le listing du disque `C:`, ce qui prouve que le serveur a lu une ressource locale choisie par l'attaquant.

![XXE : l'entité injectée renvoie un listing du système de fichiers local dans le commentaire](img/xxe-local-file-disclosure.png)

### Correctif

Désactiver les DTD et la résolution d'entités externes dans le parseur XML (pour la plupart des parseurs Java, mettre la fonctionnalité `disallow-doctype-decl` à true). CWE-611.

---

## XSS réfléchi

Dans le panier d'achat, le champ du numéro de carte est renvoyé dans la réponse du serveur sans être assaini. À la place d'un numéro de carte, j'ai entré :

```html
<script>alert('XSS')</script>
```

Au clic sur « Purchase », le serveur a réinjecté l'entrée dans la page et le navigateur l'a exécutée, affichant l'alerte. La charge utile est renvoyée de la requête vers la réponse immédiate, c'est la définition du XSS réfléchi.

![XSS réfléchi injecté via le champ de paiement du panier](img/xss-reflected-shopping-cart.png)

### Correctif

Encoder la sortie pour le contexte HTML, valider l'entrée, et ajouter une Content Security Policy pour limiter l'exécution de script inline. CWE-79.

---

## Authentification cassée

### Contournement d'authentification par suppression de paramètres

Le flux de réinitialisation de mot de passe validait deux champs de questions de sécurité, `secQuestion0` et `secQuestion1`. En interceptant la requête avec Burp et en supprimant complètement ces champs du corps, le serveur a sauté la vérification : il a validé le compte sans eux. Le serveur supposait les paramètres présents au lieu de les exiger. Cela a contourné la seconde étape et permis de réinitialiser le mot de passe sans connaître les réponses. CWE-287.

### Réinitialisation via une question de sécurité faible

Le flux de récupération reposait sur une question « couleur préférée ». L'espace des réponses est minuscule, donc un court dictionnaire manuel de couleurs courantes a suffi à la deviner et à se connecter au compte cible. Aucun verrouillage ne ralentissait les essais. CWE-640.

### Robustesse du mot de passe

Un exercice distinct demandait un mot de passe atteignant 4/4 sur le compteur de robustesse. Une passphrase plus longue avec des classes de caractères variées atteint le score maximal. La leçon : la longueur et la variété priment sur les règles de complexité.

### Correctif

Exiger les paramètres requis côté serveur et refuser par défaut. Abandonner les questions de sécurité devinables au profit de vrais flux de récupération, et ajouter du rate limiting et du verrouillage. CWE-287, CWE-640.

---

## Contrôles côté client

### Altération du prix dans le HTML

Au checkout, le total venait d'un champ caché du front-end :

```html
<input id="Total" name="Total" type="HIDDEN" value="1.0">
```

Le prix était pris depuis le client. Modifier la valeur du champ caché `Total` (via les devtools, ou dans la requête interceptée) puis soumettre la commande a fait passer l'achat au prix altéré.

### Contournement des restrictions du front-end

Un formulaire restreignait ses entrées côté client (valeurs d'options fixes, longueur maximale, champ en lecture seule). En interceptant la soumission avec Burp et en changeant ces valeurs pour des valeurs que l'UI n'autorisait pas, le serveur les a acceptées, car les restrictions n'existaient que dans le navigateur.

### Correctif

Traiter toute entrée client comme non fiable. Calculer les prix et appliquer les contraintes de champ et l'autorisation côté serveur, jamais sur des champs cachés ou la seule validation côté client. CWE-602.

---

## Outils utilisés

- Burp Suite : proxy d'interception, édition de requêtes, et Intruder pour l'injection SQL aveugle.
- Les devtools du navigateur (F12) pour inspecter et éditer les champs côté client.
- Une instance WebGoat locale comme cible.

## Récapitulatif des vulnérabilités (OWASP / CWE)

Technique ATT&CK globale : T1190 (exploitation d'une application exposée). Cartographie par vulnérabilité ci-dessous.

| Défi | Classe | CWE |
|------|--------|-----|
| Injection SQL string, chaînage de requêtes | Injection SQL | CWE-89 |
| Injection SQL UNION et aveugle | Injection SQL | CWE-89 |
| Path traversal (double encodage URL) | Path traversal | CWE-22 |
| Divulgation de fichier local via XXE | XML external entity | CWE-611 |
| XSS réfléchi | Cross-site scripting | CWE-79 |
| Contournement d'auth par suppression de paramètres | Authentification cassée | CWE-287 |
| Réinitialisation via question faible | Question de récupération faible | CWE-640 |
| Altération du prix dans le HTML | Confiance dans les contrôles côté client | CWE-602 |
| Contournement des restrictions front-end | Confiance dans les contrôles côté client | CWE-602 |

## Note sur le périmètre et l'éthique

WebGoat est une application volontairement vulnérable conçue par OWASP pour l'entraînement, exécutée ici sur une instance locale uniquement. Rien dans ce write-up n'a été testé contre un système que je ne possède pas. Le but est de montrer comment chaque classe de bug se trouve et s'exploite, pour pouvoir l'empêcher.
