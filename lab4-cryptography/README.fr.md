# Labo 4 : cryptographie appliquée et PKI avec OpenSSL

Un labo de cryptographie pratique réalisé dans un labo universitaire de sécurité des systèmes, ÉTS (Montréal), hiver 2026. Il couvre le chiffrement symétrique et asymétrique, un schéma hybride, les signatures numériques, le hachage et le cassage de mot de passe, une chaîne de certificats complète, et la mise en place de TLS sur un serveur web. Presque tout passe par OpenSSL, avec Medusa et la commande `argon2` pour les deux parties offensives.

Labo réalisé en équipe de 4, write-up et reformulation par Ilyas El Houdaigui. Aucun nom ni matricule des coéquipiers n'est inclus.

English version: [README.md](README.md).

Sommaire :

1. [Chiffrement symétrique](#chiffrement-symétrique)
2. [Chiffrement asymétrique et hybride](#chiffrement-asymétrique-et-hybride)
3. [Hachage de mot de passe avec Argon2](#hachage-de-mot-de-passe-avec-argon2)
4. [Chaîne de certificats et authentification](#chaîne-de-certificats-et-authentification)
5. [Mise en place de TLS sur un serveur web](#mise-en-place-de-tls-sur-un-serveur-web)
6. [Outils utilisés](#outils-utilisés)
7. [Récapitulatif technique et bonnes pratiques](#récapitulatif-technique-et-bonnes-pratiques)

Les deux attaques (le brute force FTP et le cassage Argon2) correspondent à MITRE ATT&CK T1110. Le reste est de la cryptographie constructive, donc les notes utiles portent sur les choix sûrs et ceux à éviter.

---

## Chiffrement symétrique

### Récupérer les fichiers : brute force FTP

Les fichiers chiffrés étaient sur un serveur FTP. Le compte `ftpuser` a été trouvé en essayant une wordlist avec Medusa :

```
medusa -h 192.168.0.188 -u ftpuser -P Passlist.txt -M ftp
```

Mot de passe : `gtilogti`. La connexion à `ftp://192.168.0.188` a ensuite donné accès aux dossiers contenant les fichiers de l'exercice (symétrique, asymétrique, hybride et hachage). C'est de la devinette de mot de passe en ligne (T1110.001).

![Medusa récupérant le mot de passe de ftpuser en FTP](img/medusa-ftp-bruteforce.png)

### Chiffrer un fichier (AES-128-CBC)

```
openssl enc -aes-128-cbc -pbkdf2 -salt -in techData -out techData.enc
```

AES-128 en mode CBC. `-pbkdf2` dérive la clé depuis la passphrase avec une vraie fonction de dérivation plutôt qu'un simple hash, et `-salt` ajoute un sel aléatoire pour que la même passphrase ne produise pas deux fois le même chiffré.

### Déchiffrer (Camellia-128-ECB)

```
openssl enc -d -camellia-128-ecb -pbkdf2 -iter 200000 -in RHSecret -out RHSecret.dec
```

Camellia est un bon chiffrement par bloc, mais le point faible est l'ECB : il chiffre chaque bloc indépendamment, donc des blocs de clair identiques donnent des blocs de chiffré identiques et les motifs fuient. Il apparaît ici comme exercice, pas comme quelque chose à utiliser pour de vraies données.

### Déchiffrement en couches (ARIA puis AES)

Un fichier était chiffré deux fois, il se retire donc en deux passes, couche externe d'abord :

```
openssl enc -d -aria-256-cbc -pbkdf2 -in SecretDT -out temp1
openssl enc -d -aes-128-cbc -pbkdf2 -in temp1 -out BankDT
```

---

## Chiffrement asymétrique et hybride

### Paire de clés RSA

```
openssl genrsa -out priv-C.pem 2048
openssl rsa -in priv-C.pem -pubout -out pub-C.pem
```

Une clé privée de 2048 bits, avec la clé publique extraite de celle-ci.

### Déchiffrer avec la clé privée du destinataire

Un fichier chiffré avec la clé publique de Bob se récupère avec la clé privée de Bob :

```
openssl pkeyutl -decrypt -in cryptofile.bin -out Datafile -inkey priv-B.pem
```

### Vérifier une signature

```
openssl dgst -sha1 -verify pub-A.pem -signature signfile.bin DataFile
# Verified OK
```

`Verified OK` confirme que le fichier a été signé par Alice et qu'il n'a pas changé. La signature utilise SHA-1 ici parce que c'est ce que le labo fournissait. Pour du réel, SHA-1 est cassé pour les signatures et il faut SHA-256 ou mieux.

![Vérification de signature renvoyant Verified OK](img/rsa-signature-verify.png)

### Chiffrement hybride

RSA ne peut pas chiffrer directement de grandes données, le schéma habituel est donc hybride : une clé de session symétrique aléatoire chiffre les données, et RSA chiffre seulement cette clé de session.

Déchiffrement (récupérer la clé de session avec la clé privée, puis l'utiliser sur le fichier) :

```
openssl pkeyutl -decrypt -in cle.key -out clekeydechifre.txt -inkey privA.pem
openssl enc -d -aes-128-ecb -in LabSecret -out LabData -K e0e0e0e0f1f1f1f1
```

Chiffrement dans l'autre sens (d'Alice vers Bob), avec un message signé :

```
openssl rand -out session.key 32
openssl enc -aes-256-cbc -salt -in LabData.sig -out LabData.sig.enc -pass file:./session.key
openssl rsautl -encrypt -pubin -inkey pub-B.pem -in session.key -out session.key.enc
```

Bob inverse le tout : `rsautl -decrypt` avec sa clé privée pour obtenir la clé de session, `enc -d -aes-256-cbc` pour récupérer le message signé, puis `dgst -verify` contre la clé publique d'Alice, qui renvoie `Verified OK`.

Cet unique échange donne les quatre propriétés à la fois :

- Confidentialité : la clé de session est enveloppée avec la clé publique de Bob, donc seul Bob peut lire le message.
- Intégrité : la signature est calculée sur les octets exacts, donc toute modification casse la vérification.
- Authenticité : seule Alice détient la clé privée qui a produit la signature.
- Non-répudiation : de ce fait, Alice ne peut pas nier ensuite l'avoir signé.

---

## Hachage de mot de passe avec Argon2

### Lire les paramètres

Après déchiffrement du fichier protégé, son contenu décrit un hash Argon2 :

```
openssl enc -d -a -camellia-128-ecb -pbkdf2 -in Securefile -out Securefile_open -pass pass:argon
```

Le record : variante Argon2i, 2 itérations, 65536 KiB (64 MiB) de mémoire, parallélisme 4, plus le hash brut et la chaîne encodée complète.

### Casser par dictionnaire

L'attaque recalcule Argon2 pour chaque candidat de `ListPwd.txt` avec les mêmes paramètres et compare au hash encodé cible :

```bash
HASH='$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$HQPq+4Ye505YrBjCPZvyPHLkWwASbyoz'
while IFS= read -r pwd; do
  printf '%s' "$pwd" | argon2 somesalt -i -t 2 -m 16 -p 4 -l 24 -e | tail -n 1 \
    | grep -Fxq "$HASH" && echo "Find: $pwd" && break
done < ListPwd.txt
# Find: log619
```

Le mot de passe est `log619` (T1110.002, cassage de mot de passe hors ligne). Tout l'intérêt d'Argon2 est justement que chaque essai coûte de la mémoire et du temps réels, ce qui rend le cassage à grande échelle coûteux. Il est tombé vite ici seulement parce que la wordlist était minuscule.

![Attaque par dictionnaire Argon2 récupérant le mot de passe](img/argon2-crack.png)

---

## Chaîne de certificats et authentification

L'objectif était de construire une PKI à trois niveaux et de la valider. Chaque niveau signe celui du dessous, jusqu'à une racine auto-signée.

```
# CA racine (auto-signée)
openssl genpkey -algorithm RSA -out CA_ME.key -pkeyopt rsa_keygen_bits:2048
openssl req -x509 -new -key CA_ME.key -sha256 -days 3650 -out CA_ME.crt -subj "/CN=CA_MELS"

# CA intermédiaire CA_UQ, signée par la racine
openssl genpkey -algorithm RSA -out CA_UQ.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key CA_UQ.key -out CA_UQ.csr -subj "/CN=CA_UQ"
openssl x509 -req -in CA_UQ.csr -CA CA_ME.crt -CAkey CA_ME.key -CAcreateserial -out CA_UQ.crt -days 3650 -sha256 -extfile v3_ca.ext

# CA émettrice CA_ETS, signée par CA_UQ (même schéma)
# Certificat feuille pour Alice, signé par CA_ETS (même schéma), CN=Alice
```

Valider la chaîne depuis Alice jusqu'à la racine, en passant les intermédiaires comme non fiables :

```
openssl verify -CAfile CA_ME.crt -untrusted <(cat CA_UQ.crt CA_ETS.crt) Alice.crt
# Alice.crt: OK
```

![Validation de la chaîne : Alice.crt remonte jusqu'à la CA racine](img/cert-chain-verify.png)

La même racine ancre une vérification de document signé avec CMS. Bob signe un fichier en y joignant les intermédiaires, et le vérificateur reconstruit la chaîne jusqu'à la racine :

```
openssl cms -sign -in tp_bob_unsigned -signer Bob.crt -inkey Bob.key \
  -certfile <(cat CA_UQ.crt CA_ME.crt) -out tp_bob_signed.pem -outform PEM -nodetach
openssl cms -verify -inform PEM -in tp_bob_signed.pem -CAfile CA_ME.crt -out tp_bob_recovered
# Verification successful
```

---

## Mise en place de TLS sur un serveur web

Générer la clé serveur et une demande de signature de certificat :

```
openssl req -newkey rsa:2048 -nodes -keyout forum.key -out forum.csr \
  -subj "/C=CN/ST=QUEBEC/L=MONTREAL/O=ETS/OU=DSI/CN=www.forum-gti619.com"
```

Créer une CA et signer le certificat serveur avec :

```
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=CN/ST=QUEBEC/L=MONTREAL/O=ETS/OU=DSI/CN=CA-GTI619"
openssl x509 -req -days 365 -in forum.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out forum.crt
```

Brancher le tout dans Apache et forcer HTTPS :

```
sudo a2enmod ssl headers
sudo a2ensite default-ssl
sudo cp forum.key /etc/ssl/private/forum.key
sudo cp forum.crt /etc/ssl/certs/forum.crt
sudo chmod 600 /etc/ssl/private/forum.key
# default-ssl.conf : SSLCertificateFile /etc/ssl/certs/forum.crt
#                    SSLCertificateKeyFile /etc/ssl/private/forum.key
# 000-default.conf : Redirect permanent / https://www.forum-gti619.com/
sudo systemctl restart apache2
```

Après le redémarrage, le HTTP simple redirige vers HTTPS et la page de connexion du forum est servie en TLS, avec le cadenas affiché.

![Le forum servi en HTTPS après la redirection](img/tls-https-forum.png)

---

## Outils utilisés

- OpenSSL pour tout le volet cryptographique : `enc`, `genrsa` et `genpkey`, `rsa`, `pkeyutl`, `rsautl`, `dgst`, `req`, `x509`, `cms` et `verify`.
- Medusa pour le brute force FTP.
- La commande `argon2` dans une boucle Bash pour l'attaque par dictionnaire.
- Apache (`a2enmod`, `a2ensite`) pour servir le site en TLS.

## Récapitulatif technique et bonnes pratiques

| Partie | Note | Référence |
|--------|------|-----------|
| Brute force FTP (Medusa) | Devinette de mot de passe en ligne | T1110.001 |
| Attaque par dictionnaire Argon2 | Cassage de mot de passe hors ligne | T1110.002 |
| Mode ECB (Camellia, AES) | Laisse fuiter les motifs du clair, à éviter | préférer un mode authentifié (AES-GCM) |
| Signatures SHA-1 | Cassé pour les signatures | utiliser SHA-256 ou plus fort |
| Dérivation de clé | PBKDF2 ou Argon2 avec un coût élevé | les avertissements OpenSSL « deprecated key derivation » pointent là |
| Gestion des clés privées | `chmod 600`, jamais lisibles par tous | moindre privilège |
| Validation PKI | Vérifier toute la chaîne jusqu'à une racine de confiance | `openssl verify` avec les intermédiaires |

## Note sur le périmètre et l'éthique

Tout a été fait sur des machines de labo montées pour l'exercice. Les mots de passe, clés et certificats montrés appartiennent à cet environnement jetable et n'ont aucune valeur ailleurs. Le brute force et le cassage de hash ont été exécutés uniquement contre les fichiers du labo.
