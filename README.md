
# anynix

CLI Rust de conditionnement et de vérification d'attestations Ed25519/BLAKE3.

Le contrat provisoire du futur registre Rails est décrit dans [API.md](API.md).

## Lancer un programme local

```sh
anynix run firefox --private-window
```

Cette commande lance le fichier régulier `/apps/bin/firefox`, sans recherche
dans `PATH`, et transmet ses arguments directement, sans shell. Le processus,
son environnement et ses accès sont ceux de l'utilisateur ; ce n'est pas une
sandbox. `--prefix /chemin` permet de choisir une autre arborescence et doit
précéder le nom du programme.

`run` ne vérifie pas lui-même la provenance ou l'intégrité de ces exécutables :
utilisez uniquement un répertoire et des fichiers de confiance. Les liens
symboliques ne sont pas acceptés pour `bin` ou le programme. La configuration
automatique des bibliothèques et `run --ephemeral` ne sont pas implémentées.

Le module Rust `release_v2` contient les premiers contrôles de schéma,
canonisation et signatures du format v2. Il ne valide pas TUF, la fraîcheur
des clés, les blobs distants ni l'exécution réelle des builds. Il n'est pas
encore relié aux commandes : `pack`, `audit` et `approve` utilisent toujours
le format source v1, qui ne constitue pas une release v2 publiable.
Un test génère temporairement une release v2 signée et un dépôt TUF local avec
une racine de test à quorum 2 sur 3. Il vérifie également les refus en cas
d'altération ou d'expiration. Ces clés et données sont uniquement destinées
aux tests.

## Installer une release locale

`install` utilise un dépôt TUF local et ne contacte aucun serveur. Cette
implémentation Unix a été testée sur Linux :

```sh
mkdir -m 700 -p "$HOME/.local/state/anynix/tuf"
anynix install example@1.0.0 \
  --repository /chemin/vers/depot \
  --trust-root /chemin/vers/racine-tuf-verifiee.json \
  --state "$HOME/.local/state/anynix/tuf"
```

Sans `@version`, la version `latest` de l'index TUF authentifié est choisie.
La racine initiale, obtenue et vérifiée indépendamment du dépôt, doit avoir
trois clés et un seuil de deux signatures. Le répertoire d'état doit être
privé, appartenir à l'utilisateur exécutant la commande et persister entre
installations pour détecter les retours arrière. Il est lié à cette racine et
ne doit pas être partagé entre dépôts distincts. La racine de confiance et
les répertoires parents du préfixe et de l'état doivent être protégés contre
les modifications d'autres utilisateurs ; les liens symboliques dans ces
chemins sont refusés.

Le dépôt contient `metadata/` et `targets/` pour TUF, ainsi que `blobs/` avec
un fichier nommé par hash BLAKE3 pour chaque fichier à installer. Les cibles
TUF requises sont la politique de clés `anynix/attestation-keys.json`, les
index `anynix/packages/<nom>.json` et les releases
`anynix/releases/<nom>/<version>.json`. Les cibles TUF déléguées ne sont pas
encore prises en charge. Les archives source de `pack` ne sont pas installables.

Le client vérifie TUF, les cinq signatures, l'index, la cible courante et les
hashes des fichiers, puis résout les dépendances exactes dans le même dépôt.
Les chemins sont installés sous `/apps`, ou sous `--prefix /chemin` si indiqué.
Le préfixe et les répertoires utilisés doivent appartenir à l'utilisateur
exécutant la commande et ne pas être modifiables par d'autres utilisateurs.
L'accès à `/apps` peut nécessiter des droits appropriés. Aucun fichier existant
n'est écrasé : une réinstallation ou une dépendance déjà présente peut donc
échouer. En cas d'erreur pendant la copie, les fichiers créés sont supprimés
si possible ; une interruption brutale peut laisser une installation partielle.
La suppression et le suivi des fichiers installés ne sont pas encore disponibles.

## Confiance et clés

Chaque rôle possède une clé publique approuvée localement. Le répertoire est
`$ANYNIX_TRUST_DIR`, ou `~/.config/anynix/trust` par défaut. Installez-y les
clés publiques **après vérification par un canal indépendant** :
`developer.pem`, `reviewer.pem`, `manager.pem`, `build-server.pem` et
`release-authority.pem`. Seules les clés nécessaires aux étapes présentes sont
requises. Protégez ce répertoire contre les modifications non autorisées.
La clé embarquée ne constitue pas à elle seule une preuve d'identité.

`anynix keygen --role developer --out developer.key` crée la clé privée PKCS#8
PEM (permissions 0600 sur Unix) et la clé publique `developer.key.pub.pem`.
Ne partagez jamais les clés privées ; elles ne sont pas chiffrées.

Exemple de configuration locale pour les trois premiers rôles :

```sh
mkdir -p "$HOME/.config/anynix/trust"
anynix keygen --role developer --out developer.key
anynix keygen --role reviewer --out reviewer.key
anynix keygen --role manager --out manager.key
cp developer.key.pub.pem "$HOME/.config/anynix/trust/developer.pem"
cp reviewer.key.pub.pem "$HOME/.config/anynix/trust/reviewer.pem"
cp manager.key.pub.pem "$HOME/.config/anynix/trust/manager.pem"
```

En production, chaque rôle conserve sa propre clé privée séparément et les
clés publiques sont distribuées et vérifiées indépendamment.

## Parcours

Avant `pack`, créez `anynix.yaml` dans le répertoire source :

```yaml
build_script: "build.script"
include:
  - "src/**"
  - "README.md"
```

La liste est obligatoire. Les chemins et motifs glob sont relatifs au
répertoire source ; un répertoire sélectionné inclut son contenu. Les fichiers
exclus par `.ignore` ou `.gitignore` ne sont pas inclus, même s'ils
correspondent à un motif. Le répertoire `.git` est toujours exclu. Seuls les
fichiers et répertoires sont acceptés ; les liens et fichiers spéciaux sont
refusés. Le fichier `anynix.yaml` lui-même n'est inclus que s'il est sélectionné.
`build_script` est relatif au répertoire source ; son contenu est inclus
séparément dans l'archive et n'est pas exécuté par `pack`.

Pour utiliser `anynix pack` sans argument, créez une clé personnelle une seule
fois :

```sh
mkdir -p "$HOME/.config/anynix/keys"
anynix keygen --role developer --out "$HOME/.config/anynix/keys/developer.pem"
```

Depuis le répertoire source, `anynix pack` utilise `anynix.yaml`, la clé
ci-dessus et crée `package.anynix` dans le répertoire courant. Il refuse
d'écraser une archive existante. Les options `--script`, `--key`, `-o` et le
chemin source restent disponibles et remplacent ces valeurs par défaut ; un
chemin `--script` est relatif au répertoire courant. La clé privée ne doit
jamais être incluse dans l'archive.

```sh
anynix pack ./source --script ./build.script --key developer.key -o package.anynix
anynix submit package.anynix
anynix ls package.anynix
anynix audit package.anynix --key reviewer.key
anynix approve package.anynix --key manager.key --cpu 4 --thread 4 --memory 4G
anynix unpack package.anynix -o ./extracted
```

Le reviewer peut aussi rejeter le paquet :

```sh
anynix reject package.anynix --reason "Corrections requises" --key reviewer.key
```

La décision et le motif sont signés. Un paquet rejeté ne peut être soumis,
approuvé ou extrait ; le développeur crée un nouveau paquet corrigé, le soumet
à nouveau, et le reviewer le réexamine. Sans option `--server`, `submit`
ne fait qu'une vérification locale et n'envoie rien.

Pour comparer les sources d'une archive signée, y compris rejetée, avec le
répertoire local :

```sh
anynix diff package.anynix .
```

Le répertoire local doit contenir `anynix.yaml` ; seules les sources
sélectionnées par ce fichier et ses règles d'exclusion sont comparées. Le
script inclus séparément dans l'archive n'est pas comparé, sauf s'il fait
également partie des sources sélectionnées. La commande exige Git.

Après avoir poussé les corrections vers le dépôt Git distant :

```sh
anynix update package.anynix -o corrected.anynix
anynix submit corrected.anynix
```

`update` utilise par défaut `origin` du dépôt courant et la branche par défaut
du serveur ; `--repository` et `--branch` permettent de les préciser. Il clone
le dépôt dans un répertoire temporaire, prend uniquement les fichiers du commit
récupéré, applique le `anynix.yaml` de ce commit et affiche son identifiant.
Les modifications locales non commitées ne sont pas incluses. Les liens,
fichiers spéciaux et sous-modules ne sont pas pris en charge. La clé Developer
utilisée doit être la même que celle de l'archive précédente et être approuvée
localement ; `--key` permet de la préciser. Le commit et l'origine affichés ne
constituent pas une preuve d'origine Git et ne sont pas enregistrés dans le
manifeste signé.

Cette commande crée une nouvelle archive avec les seules sources mises à jour
et une nouvelle signature Developer ; elle conserve l'ancienne archive intacte
et refuse d'écraser la destination. Elle ne transmet rien : le lien de correction
est créé par `submit --server ... --correction-of ...` décrit ci-dessous.

`audit` vérifie les signatures, les clés approuvées, l'intégrité et la
structure du payload ; il n'exécute pas le script et ne remplace pas une revue
humaine. `unpack` vérifie les signatures existantes mais **n'exige pas** que le
paquet ait atteint le statut ReleaseAuthority. Il crée une nouvelle destination
et refuse les liens et fichiers spéciaux. Utilisez un répertoire parent de
destination contrôlé par l'utilisateur.

## Service privé de revue

Le service est un processus distinct du registre public. Il conserve en SQLite
les soumissions, les décisions signées, les motifs et les liens de correction,
même après redémarrage. **Tous les comptes authentifiés peuvent consulter
toutes les soumissions et tous les motifs**, y compris ceux des autres
développeurs. Seul un Developer peut soumettre ou corriger ses propres
soumissions refusées ; seul un Reviewer peut approuver ou refuser une
soumission en attente ; seul un Manager peut signer une soumission approuvée
par un Reviewer. L'administration des comptes est manuelle.

Chaque compte utilise un jeton distinct et chaque signataire une clé Ed25519
distincte. Le service vérifie que la clé de signature correspond au compte
authentifié et que chaque décision porte sur l'archive précédente. Les clés et
les jetons sont chargés au démarrage ; redémarrer le service après modification
de sa configuration. Ne réutilisez pas un identifiant de compte pour une autre
personne. La vérification locale des commandes utilise toujours
`ANYNIX_TRUST_DIR` : lorsqu'il y a plusieurs développeurs ou reviewers, choisir
un répertoire de confiance contenant les clés des signataires de l'archive.

Pour créer un jeton individuel dans fish, sur la machine de son titulaire :

```fish
set -gx ANYNIX_REVIEW_TOKEN (openssl rand -hex 32)
anynix review token-hash
```

Le titulaire conserve le jeton secret et transmet uniquement le hash affiché à
l'administrateur par un canal fiable. N'utilisez pas les exemples ci-dessous
comme de vrais jetons. L'administrateur crée un fichier JSON privé, avec un
compte par personne et les clés publiques préalablement vérifiées :

```json
{
  "accounts": [
    {"id": "alice", "role": "Developer", "token_hash": "<hash-alice>", "public_key": "/chemin/alice.pub.pem"},
    {"id": "reviewer", "role": "Reviewer", "token_hash": "<hash-reviewer>", "public_key": "/chemin/reviewer.pub.pem"},
    {"id": "manager", "role": "Manager", "token_hash": "<hash-manager>", "public_key": "/chemin/manager.pub.pem"}
  ]
}
```

Chaque hash doit comporter 64 caractères hexadécimaux minuscules. Protégez le
fichier de configuration, le répertoire de la base, leurs parents et les
sauvegardes ; le service exige un fichier de configuration privé et un
répertoire de base privé appartenant à son utilisateur :

```sh
mkdir -m 700 -p /chemin/prive
chmod 600 /chemin/prive/review.json
anynix review serve --config /chemin/prive/review.json \
  --database /chemin/prive/review.sqlite
```

Le service écoute uniquement sur l'interface locale, par défaut
`127.0.0.1:3456`. Pour y accéder depuis une autre machine, utilisez un tunnel
SSH ou un proxy HTTPS privé correctement configuré ; ne publiez pas le port
HTTP directement. Le client accepte HTTP uniquement pour une adresse loopback
numérique et exige HTTPS ailleurs, sans suivre les redirections.

Exemple de parcours (chaque participant utilise son propre jeton et ses clés) :

```sh
# Developer : première soumission
anynix submit package.anynix --server http://127.0.0.1:3456

# Tous les comptes authentifiés peuvent consulter l'historique
anynix review list --server http://127.0.0.1:3456

# Reviewer : récupérer, examiner, puis approuver OU refuser
anynix review get 1 --server http://127.0.0.1:3456 -o review.anynix
anynix diff review.anynix /chemin/vers/sources
anynix audit review.anynix --key reviewer.key
# ou : anynix reject review.anynix --reason "Corrections requises" --key reviewer.key
anynix review send 1 review.anynix --server http://127.0.0.1:3456

# Developer, après refus : créer et transmettre une correction liée
anynix review get 1 --server http://127.0.0.1:3456 -o rejected.anynix
anynix update rejected.anynix -o corrected.anynix
anynix submit corrected.anynix --server http://127.0.0.1:3456 --correction-of 1

# Manager, après approbation du Reviewer : récupérer et signer
anynix review get 2 --server http://127.0.0.1:3456 -o manager.anynix
anynix approve manager.anynix --key manager.key --review-only
anynix review send 2 manager.anynix --server http://127.0.0.1:3456
```

Les identifiants `1` et `2` sont des exemples : utilisez ceux renvoyés par le
service et faites examiner la correction avant l'étape Manager. `review get`
télécharge le dernier état ; `--original` récupère l'archive Developer initiale
et `--reviewer` la décision Reviewer même après l'approbation Manager. Les
fichiers téléchargés ne remplacent jamais un fichier existant et doivent être
vérifiés avec `ls`, `audit` ou `approve` avant utilisation.

La transmission est disponible par consultation du service, sans notification
automatique. Aucun build ni aucune publication n'est lancé par le service.
Les attestations source v1 ne lient pas leur signature à l'identifiant de
soumission ; une même décision signée peut donc être réutilisée pour des
soumissions au contenu identique par le même signataire authentifié. Le service
ne prouve pas non plus qu'une correction concerne le même paquet : le format
source v1 ne signe ni nom ni version de paquet. L'administrateur doit assurer
la séparation des personnes et des rôles. Le service ne fournit pas encore de
rotation automatisée, de quotas, de limitation de
débit, de sauvegardes ni de protection contre le rollback de sa base. Ne
l'exposez pas en production sans revue de sécurité et mesures d'exploitation
complémentaires.

## Format et limites

L'archive zstd contient exactement `payload.tar.zst`, `build.script` et
`manifest.json`. Les signatures portent sur un BLAKE3 d'une représentation
JSON déterministe, avec séparation de domaine, hashes du payload et du script,
hash de l'attestation précédente, rôle, décision, motif éventuel, clé publique
et hashes des sorties. Les étapes sont ordonnées Developer, Reviewer, Manager,
BuildServer et ReleaseAuthority ; la dernière étape de build nécessite les
hashes Linux, FreeBSD et Haiku. Les mises à jour ne recompressent pas le
payload interne. Les archives compressées sont limitées à 256 Mio et les tar
décompressés à 512 Mio ; le script et le manifeste sont limités à 1 Mio chacun.
Les binaires ne sont pas inclus dans ce format : leurs hashes attestés ne
pourront être comparés aux fichiers produits qu'une fois l'intégration de build
distante réalisée.

Les signatures n'empêchent pas la suppression des dernières attestations ni le
remplacement par une ancienne archive valide. Une protection contre le rollback
exige un registre externe de versions/états, qui n'est pas encore implémenté.
Les clés d'un rôle ne sont pas un mécanisme de révocation ou de rotation.

Proxmox, la construction distante, les attestations BuildServer et
ReleaseAuthority automatiques et SSH sont des **mocks non opérationnels**.
`approve` enregistre d'abord la signature Manager, puis retourne une erreur
indiquant qu'aucun build n'a été lancé. Aucune signature de build ou de release
n'est simulée. La substitution de chemins existe pour Linux, FreeBSD, OpenBSD
et Haiku, mais aucun script n'est exécuté.
