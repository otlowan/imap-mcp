# Relecture de sécurité — imap-mcp

- **Dépôt d'origine** : https://github.com/LeeFlannery/imap-mcp
- **Commit relu** : `51929b3c3ce19b8f5167965ac70eb43b04fa175c` (branche `main`, 24/09/2026)
- **Date** : 14/11/2026
- **Périmètre** : tout le code (`src/imap_mcp/*.py`, 4 fichiers, ~300 lignes), les tests,
  `pyproject.toml`, `uv.lock` (46 paquets), la CI, et le code des bibliothèques réellement
  appelées (`imap-tools` 1.14.0, `imaplib` de CPython 3.12 / 3.13 / 3.14).
- **Modèle de menace** : un agent IA (modèle local) appelle les outils. Le contenu des mails
  est **non fiable** (injection de prompt) : un mail peut pousser le modèle à appeler un outil
  avec des arguments choisis par l'attaquant. Le serveur ne doit jamais pouvoir modifier une
  boîte, ni divulguer les mots de passe, ni joindre autre chose que les serveurs IMAP configurés.

Méthode : lecture complète du code, inspection du code source des bibliothèques appelées,
preuve de concept contre un **faux serveur IMAP local** (aucun vrai compte utilisé), analyse
du lockfile contre la GitHub Advisory Database, inspection du certificat réel de Proton Bridge.

---

## 1. Commandes IMAP envoyées

Chemin d'exécution : `open_box()` → `MailBox.login()` → `fetch()` → `logout()`.

| Commande | Où | Remarque |
|---|---|---|
| `CAPABILITY` | connexion (imaplib) | lecture |
| `LOGIN "<email>" "<mot de passe>"` | `open_box` → `BaseMailBox.login` | arguments mis entre guillemets par imaplib |
| **`SELECT "INBOX"`** | `login(initial_folder="INBOX")` → `folder.set(readonly=False)` | ⚠️ **lecture/écriture** (voir constat M1) |
| `UID SEARCH CHARSET US-ASCII <critères>` | `fetch()` → `uids()` | critères construits par imap-tools (`OR`/`AND`, `UID`, `SINCE`, `UNSEEN`) |
| `UID FETCH <uids> (BODY.PEEK[] UID FLAGS RFC822.SIZE)` | `fetch(mark_seen=False)` | ✅ **PEEK** partout : ne pose jamais `\Seen` |
| `LOGOUT` | `open_box` (finally) | |

**Commandes d'écriture ou de marquage dans le code du projet** : **aucune**.
`STORE`, `COPY`, `MOVE`, `EXPUNGE`, `APPEND`, `DELETE`, `CREATE`, `RENAME`, `SUBSCRIBE` et
`FETCH` sans `PEEK` n'apparaissent pas. Les deux appels à `fetch()` passent `mark_seen=False`.
La bibliothèque imap-tools **contient** ces opérations (`box.delete()`, `box.move()`,
`box.flag()`, `box.folder.create()`…) mais le projet ne les appelle pas.

⚠️ Cette garantie « par construction » est **contournable** sous Python 3.12 (constat C2).

## 2. Ouverture des dossiers

`MailBox.login(..., initial_folder="INBOX")` appelle `folder.set("INBOX")`, dont le paramètre
`readonly` vaut `False` par défaut. Résultat : **`SELECT`** (lecture/écriture) et non
**`EXAMINE`** (lecture seule). Un seul dossier est utilisé : INBOX.

## 3. Appels réseau

- **Seul appel réseau du projet** : la connexion imaplib vers `host:port` de chaque compte.
- Aucun `requests`, `urllib`, `httpx`, `socket` direct, ni télémétrie dans `src/`.
- `mcp` dépend de `opentelemetry-api`, mais sans SDK ni exporteur installé : c'est une API
  vide (aucun envoi). Vérifié : `opentelemetry.sdk` absent.
- `mcp.run()` démarre en **stdio** par défaut (aucun port ouvert).
- ⚠️ **Mais la connexion TLS n'est pas vérifiée** (constat C1) : un attaquant sur le chemin
  réseau peut se faire passer pour le serveur IMAP.

## 4. Gestion des secrets

- ✅ Les mots de passe ne sont **jamais** dans `accounts.toml` : chaque compte nomme une
  variable d'environnement (`password_env`). `accounts.toml`, `.env*` et `*.secret` sont dans
  `.gitignore`.
- ✅ Aucun `logging` ni `print` dans le code ; imaplib n'est pas en mode debug.
- ✅ `list_accounts` ne renvoie que le **type** d'exception.
- ⚠️ `list_emails` / `search_emails` renvoient `f"{type(e).__name__}: {e}"`. Pour une erreur
  imap-tools, le texte contient la **réponse du serveur** (ex. `[AUTHENTICATIONFAILED]`), pas la
  commande envoyée. **Aucune fuite de mot de passe n'a été trouvée**, mais ces messages bruts
  partent vers le modèle (constat F1).

## 5. Exécution de commandes, eval, fichiers

- Aucun `subprocess`, `os.system`, `eval`, `exec`, `pickle`.
- Aucune écriture de fichier. Seule lecture : `accounts.toml` (chemin par défaut relatif au
  paquet, ou `$IMAP_MCP_ACCOUNTS`).

## 6. Dépendances

Directes : `imap-tools>=1.13.0`, `mcp[cli]>=1.28.1` ; dev : `pytest`, `ruff`.
Le lockfile fige **46 paquets** (tous depuis pypi.org, avec empreintes sha256) :

| Paquet | Version figée | Origine / réputation | Remarque |
|---|---|---|---|
| imap-tools | 1.14.0 | ikvk/imap_tools, projet ancien et répandu, **zéro dépendance** | dernière : 1.16.0 |
| mcp, mcp-types | 2.0.0 | SDK officiel Model Context Protocol (LF Projects) | ⚠️ 4 avis *medium* corrigés en 2.2.0 (M5) ; dernière : 2.3.0 |
| httpx2, httpcore2 | 2.12.0 | fork de httpx maintenu par Pydantic (Tom Christie) ; **dépendance officielle de mcp 2.x** | nom inhabituel mais légitime (vérifié sur PyPI) |
| httpx2-jsfetch | 1.0 | seulement pour emscripten (navigateur) | jamais installé ici |
| pyjwt (+cryptography, cffi, pycparser) | 2.13.0 / 50.0.0 | via mcp (auth HTTP) | ⚠️ pyjwt ≤ 2.13.0 : plusieurs avis *high* (M5) |
| starlette, sse-starlette, uvicorn, h11, python-multipart | 1.3.1 / 3.4.6 / 0.52.1 / 0.16.0 / 0.0.32 | via mcp (transports HTTP) | versions figées non vulnérables ; inutilisées en stdio |
| pydantic, pydantic-core, jsonschema, referencing, rpds-py, attrs, anyio, idna, truststore, typing-* , annotated-types | — | via mcp | pas d'avis ouvert sur les versions figées |
| opentelemetry-api | 1.44.0 | via mcp | API vide sans SDK |
| **typer, rich, click, shellingham, python-dotenv, markdown-it-py, mdurl, pygments, colorama, annotated-doc** | — | via l'extra **`mcp[cli]`** | ⚠️ **superflues** à l'exécution (outil `mcp dev`) (F3) |
| pywin32 | 312 | Windows uniquement | jamais installé ici |
| pytest, ruff, iniconfig, pluggy, packaging | — | dev uniquement | |

## 7. Contenu des mails

- `get_email` renvoie `body` = `text` ou, à défaut, **le HTML brut**, **sans limite de taille**.
- `list_emails` / `search_emails` téléchargent **le message complet** (`BODY.PEEK[]`, pièces
  jointes comprises) pour chaque ligne, juste pour un extrait de 200 caractères, en **une seule
  commande** (`bulk=True`), sans plafond sur `limit` et sans timeout réseau.
- Les pièces jointes ne sont **pas** renvoyées au modèle (seulement téléchargées).
- Le contenu n'est pas signalé comme « non fiable » dans les réponses.

---

## Constats classés

### 🔴 Critique

**C1. Certificats TLS jamais vérifiés.**
`MailBox(host, port)` sans `ssl_context` → imaplib utilise `ssl._create_stdlib_context()`,
qui est **`_create_unverified_context`** : `verify_mode=CERT_NONE`, `check_hostname=False`
(vérifié sur Python 3.14.8, code identique en 3.12/3.13). N'importe qui sur le chemin réseau
(Wi-Fi, DNS empoisonné, routeur compromis) peut présenter un faux certificat et **récupérer les
mots de passe** (mot de passe d'application Gmail, Mailo) ainsi que les mails.
→ *Correctif* : contexte `ssl.create_default_context()` systématique (vérification ACTIVE),
`ca_file` / `tls_server_name` pour Bridge.

**C2. Injection de commandes IMAP par retour à la ligne dans `search_emails(query=…)`
sous Python 3.12** (version figée par `.python-version`).
imap-tools met la requête entre guillemets mais **conserve CR/LF**. CPython **3.13+** refuse
ces caractères dans imaplib (`ValueError: NUL, CR and LF not allowed in commands`, vérifié par
preuve de concept), mais **CPython 3.12 n'a pas cette protection** (vérifié dans le code source
de la branche 3.12, 3.12.16+). Un mail piégé peut amener le modèle à chercher
`x\r\nA1 UID STORE 1:* +FLAGS (\Deleted)\r\nA2 EXPUNGE\r\n…` : imaplib 3.12 envoie alors ces
lignes au serveur comme **commandes indépendantes**. Combiné au `SELECT` en lecture/écriture
(M1), cela permet de **supprimer des mails**, et plus largement d'envoyer n'importe quelle
commande (`DELETE` de dossier, `SELECT` d'un autre dossier puis `STORE`, etc.). La promesse
« lecture seule par construction » est donc **fausse sous Python 3.12**.
→ *Correctif* : validation stricte de **tous** les arguments des outils (refus des caractères de
contrôle, `id` = chiffres uniquement), indépendamment de la version de Python ; Python ≥ 3.13
recommandé en défense en profondeur ; EXAMINE (M1) comme second rempart.

### 🟠 Moyen

**M1. INBOX ouvert en `SELECT` (lecture/écriture) au lieu d'`EXAMINE`.** Aucune écriture n'est
envoyée en fonctionnement normal, mais il n'y a aucun second rempart si une commande d'écriture
passait (C2). `SELECT` peut aussi effacer le drapeau de session `\Recent` sur certains serveurs.
→ `folder.set("INBOX", readonly=True)`.

**M2. `get_email(id=…)` accepte des ensembles d'UID** (`1:*`, `*`, `1,2,3`) : imap-tools les
valide comme ensembles légitimes. `id="1:*"` télécharge **toute la boîte** message par message
(saturation mémoire/temps, volume énorme de données), pour ne renvoyer que le premier.
→ `id` = entier décimal positif strict ; fetch par `uid_list`.

**M3. Ressources non bornées** : `limit` sans plafond, téléchargement du message complet (pièces
jointes comprises) pour chaque ligne de liste, une seule commande `UID FETCH` pour tout, aucun
timeout réseau (un serveur muet bloque l'outil indéfiniment).
→ plafonner `limit` ; liste = en-têtes + taille, extrait seulement pour les messages de taille
raisonnable ; `timeout` sur la connexion.

**M4. Corps renvoyé sans limite, HTML brut en repli.** Un seul mail peut saturer la fenêtre de
64K tokens du modèle ; le HTML brut gonfle le volume et cache du texte invisible (injection de
prompt dans des balises masquées).
→ `max_body_chars` (défaut 20000) + mention « [tronqué] » ; conversion HTML → texte (bibliothèque
standard, sans nouvelle dépendance) quand il n'y a pas de partie texte.

**M5. Dépendances figées avec avis connus** : `mcp` 2.0.0 (4 avis *medium*, corrigés en 2.2.0 :
authentification bearer, redirections, `$ref` distants, sessions StreamableHTTP non bornées) et
`pyjwt` 2.13.0 (plusieurs avis *high*, corrigés en 2.14.0). **Non exploitables en stdio** (code
HTTP/auth non utilisé), mais ils le deviendraient en mode HTTP.
→ mettre à jour le lockfile (`mcp` ≥ 2.2, `pyjwt` ≥ 2.14).

### 🟡 Faible

**F1. Messages d'erreur bruts renvoyés au modèle** (texte serveur, noms d'hôte). Pas de fuite de
secret constatée. → messages d'erreur normalisés et courts.

**F2. Recherche avec accents impossible** : `SEARCH CHARSET US-ASCII` + encodage ASCII →
`UnicodeEncodeError` sur « été ». Fonctionnel, pas sécuritaire. → `CHARSET UTF-8` si non-ASCII.

**F3. Extra `mcp[cli]` superflu** : 10 paquets inutiles à l'exécution (typer, rich, click…).
→ dépendre de `mcp` sans extra.

**F4. Chemin de configuration par défaut relatif au paquet** : faux une fois le paquet installé
(non éditable). → documenter/privilégier `IMAP_MCP_ACCOUNTS`.

**F5. `.python-version` = 3.12** : prive de la protection CR/LF d'imaplib 3.13+.
→ passer à 3.13 (et `requires-python >= 3.13`).

**F6. Contenu non marqué comme non fiable.** → ajouter dans les réponses un champ indiquant que
`body`/`snippet`/`subject` sont du contenu externe non fiable (aide au cadrage côté agent).

### ✅ Points positifs

- `mark_seen=False` → `BODY.PEEK` sur **tous** les fetch ; aucun code d'écriture dans le projet.
- Aucun appel réseau autre qu'IMAP, aucune télémétrie, aucune exécution système, aucune écriture
  de fichier.
- Mots de passe hors fichiers, dans l'environnement ; `.gitignore` prudent.
- Pièces jointes jamais renvoyées au modèle ; arguments `since` validés (`date.fromisoformat`).
- Code court et lisible, 31 tests qui passent, dépendances figées par empreintes.

---

## Verdict

**Le code n'est pas sain en l'état** : deux constats critiques (TLS non vérifié, injection de
commandes IMAP sous Python 3.12) contredisent directement les deux garanties attendues (« ne
jamais modifier une boîte », « ne parler qu'aux serveurs IMAP configurés »). En revanche la base
est **petite, lisible et saine dans sa conception** (PEEK partout, aucune écriture volontaire,
aucun appel réseau parasite) : tous les constats sont corrigeables dans le cadre du durcissement
prévu, sans réécriture.

## Annexe — certificat Proton Bridge observé (instance de test)

- Auto-signé, `CN=127.0.0.1`, `O=Proton AG`, `CA:TRUE`, SAN **`IP:127.0.0.1` uniquement**
  (aucun nom DNS), valable jusqu'en 2046, sans *Subject Key Identifier*.
- Empreinte SHA-256 : `<empreinte SHA-256 du certificat observé>` (propre à chaque installation de Bridge)
- Même certificat sur 1143 (Bridge) et 143 (relais socat).
- `openssl verify -CAfile cert -verify_ip 127.0.0.1` : OK ; `-verify_hostname proton-bridge` : échec
  (attendu). → Connexion à `proton-bridge`, vérification **contre l'IP 127.0.0.1** (`tls_server_name`).
  Python vérifie correctement les SAN de type IP ; l'épinglage d'empreinte reste utile en
  défense en profondeur. Point à tester : le mode `VERIFY_X509_STRICT` activé par défaut depuis
  Python 3.13 pourrait refuser ce certificat (absence de *Subject Key Identifier*).
