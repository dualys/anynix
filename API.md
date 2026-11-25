# Registre anynix : proposition d'API v1

Ce document décrit un contrat **provisoire** pour le futur service Rails.
Aucune de ces routes n'est encore implémentée par le client ou par un serveur
dans ce dépôt. Le service interne de revue et de transfert est distinct du
registre public et n'est pas défini ici.

## Conventions

- URL de base HTTPS configurable ; toutes les routes ci-dessous sont relatives
  à cette URL et commencent par `/v1`.
- JSON UTF-8 pour les métadonnées ; fichiers binaires téléchargés séparément.
- Un paquet est identifié par son nom et une version exacte. Le registre ne
  doit pas permettre de remplacer une version déjà publiée.
- Les réponses d'erreur sont des objets JSON `{"error": "..."}` avec un statut
  HTTP approprié : 400 (requête invalide), 401/403 (accès refusé), 404 (absent),
  409 (conflit ou version déjà publiée) et 422 (validation impossible).
- Le registre public contient uniquement des releases finalisées, pas les
  contacts, tâches ou décisions internes.

## Consultation

| Méthode et route | Utilisation |
| --- | --- |
| `GET /v1/packages?query=...` | Rechercher des paquets publiés. |
| `GET /v1/packages/{name}` | Métadonnées publiques et versions disponibles. |
| `GET /v1/packages/{name}/releases/latest` | Dernière release publiée. |
| `GET /v1/packages/{name}/releases/{version}` | Release publiée d'une version exacte. |
| `GET /v1/blobs/{blake3}` | Télécharger un fichier identifié par son hash BLAKE3. |
| `GET /v1/keys/{fingerprint}` | Obtenir une clé publique et ses informations de validité. |

Une release doit décrire son nom, sa version, sa licence, les sources quand
elles sont disponibles, la chaîne complète d'attestations et les cibles
`os`/`architecture`. Pour chaque cible, elle doit lister les dépendances
avec leurs versions, et les fichiers avec leur hash BLAKE3, leur taille, leur
destination, leurs permissions et leur type (binaire, configuration,
documentation, page de manuel ou source). Les chemins doivent être validés
avant toute installation ; les liens symboliques sont interdits.

Le client vérifie les cinq signatures et les hashes **avant** de faire
confiance aux métadonnées ou d'installer un fichier. Une clé téléchargée ou
embarquée n'est pas automatiquement approuvée : la confiance part d'une clé
racine installée ou vérifiée indépendamment. Les métadonnées de release, les
dépendances et la liste des fichiers doivent être liées cryptographiquement aux
attestations, pas uniquement protégées par HTTPS.

Le manifeste source actuel, version 1, ne signe pas encore ces métadonnées
d'installation et ne permet d'attester que trois sorties nommées. Il faut
définir et implémenter un format de release versionné, signé et interopérable
avant de considérer ces réponses comme installables.

## Publication

| Méthode et route | Utilisation |
| --- | --- |
| `POST /v1/blobs` | Téléverser un fichier candidat ; le serveur calcule et vérifie son hash. |
| `POST /v1/releases` | Demander la publication d'une release construite et signée. |
| `GET /v1/publications/{id}` | Consulter l'état d'une demande de publication. |

Seul un manager autorisé peut demander une publication. Le serveur doit
vérifier les signatures, les hashes et la politique des cibles requises avant
de rendre une release publique. Une erreur de build sur une cible obligatoire
bloque la publication ; les autres échecs sont signalés. La liste des cibles
obligatoires doit être maintenue explicitement : un système ne peut pas être
considéré pris en charge avant que son build et son installation soient testés.

L'authentification, les schémas JSON exacts, la rotation/révocation des clés,
la politique des cibles et la signature canonique du format de release restent
à spécifier conjointement avec l'implémentation Rails. Aucun protocole de
transfert interne ni point de terminaison de revue n'est exposé par cette API
publique.

## Utilisation prévue par le client

- `pull nom` : métadonnées pour l'OS et l'architecture courants.
- `pull nom --complete` : métadonnées de toutes les cibles disponibles.
- `pull nom --offline` : archive autonome pour la cible courante, dépendances
  et sources applicables comprises.
- `pull nom --complete --offline` : archive autonome pour toutes les cibles.
- `install nom[@version]` : installation de la cible courante, après
  vérification et résolution des dépendances.
- `remove` et `uninstall` : commandes synonymes.

Ces commandes ne sont pas encore implémentées. L'installation hors ligne ne
doit effectuer aucune requête réseau, y compris pour les clés et dépendances ;
les éléments nécessaires doivent déjà être disponibles localement.
