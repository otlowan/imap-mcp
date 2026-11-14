# imap-mcp — fork durci

> **Fork durci** de [LeeFlannery/imap-mcp](https://github.com/LeeFlannery/imap-mcp)
> (commit d'origine `51929b3c`). Voir la section [Fork durci](#fork-durci) et
> [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md).

All your mailboxes, one MCP server, read-only.

Point it at any number of IMAP accounts (Gmail, Fastmail, iCloud, Migadu,
self-hosted, anything that speaks IMAP) and your MCP client can list, search,
and read across every one of them in a single call. Ask "what's unread across
all my accounts?" or "find the invoice from Hetzner" and get answers that span
providers, not one inbox at a time.

**Strictly read-only.** No send, no delete, no flag changes, no folder moves.
Every fetch uses `BODY.PEEK`, so reading a message never marks it as read.
Your mailboxes look exactly the same after a session as before it.

**No secrets on disk.** The config file names an environment variable per
account; passwords only ever exist in the server process environment. Bring
your own secret manager, or just export a variable.

## Fork durci

Ce fork part du commit `51929b3c` de l'original et corrige les constats de la
relecture de sécurité ([`SECURITY_REVIEW.md`](SECURITY_REVIEW.md)). Il reste en
**lecture seule par construction** et n'ajoute **aucune** fonction d'écriture,
d'envoi, de suppression ou de déplacement.

### Différences avec l'original

| Sujet | Original | Fork durci |
|---|---|---|
| Certificats TLS | **jamais vérifiés** (contexte imaplib par défaut, `CERT_NONE`) | toujours vérifiés (`ssl.create_default_context`, TLS ≥ 1.2) |
| Modes TLS | TLS implicite (993) seulement | `ssl` (993) ou `starttls` (143), **sans repli en clair** |
| Certificat auto-signé (Proton Bridge) | impossible | `ca_file`, `tls_server_name`, `tls_fingerprint_sha256` |
| Ouverture d'INBOX | `SELECT` (lecture/écriture) | `EXAMINE` (lecture seule) |
| Commandes IMAP | celles qu'imap-tools envoie | **liste blanche** au niveau du transport : `CAPABILITY`, `STARTTLS`, `LOGIN` (chiffré uniquement), `EXAMINE`, `UID SEARCH`, `UID FETCH` avec `BODY.PEEK`, `NOOP`, `LOGOUT` ; tout le reste est bloqué avant d'atteindre le réseau |
| Injection CR/LF dans `search_emails` | possible sous Python 3.12 (commandes IMAP arbitraires) | refusée (validation des arguments + garde du transport) ; Python ≥ 3.13 |
| `get_email(id)` | accepte `1:*` (toute la boîte) | un seul UID numérique |
| `limit` | illimité | plafonné à 100 par compte |
| Liste / recherche | télécharge chaque message entier (pièces jointes comprises) | en-têtes d'abord ; corps seulement pour les messages ≤ 256 Ko (extrait) |
| Corps de `get_email` | illimité, HTML brut en repli | tronqué à `max_body_chars` avec « [tronqué] » ; HTML converti en texte |
| Newsletters | — | champ `list_unsubscribe` (en-tête `List-Unsubscribe` présent) |
| Contenu externe | non signalé | champ `untrusted_content: true` sur chaque réponse |
| Erreurs renvoyées au modèle | texte brut du serveur | messages courts et normalisés, sans secret |
| Timeout réseau | aucun | 30 s par défaut (`timeout_seconds`) |
| Recherche avec accents | échoue (US-ASCII) | `CHARSET UTF-8` automatique |
| Dépendances | `mcp[cli]` 2.0.0, pyjwt 2.13.0 (avis GHSA) | `mcp` 2.3.0 sans extra, pyjwt ≥ 2.14 ; 39 paquets figés au lieu de 46 |

### Nouvelles options

Par compte (`[[account]]`), toutes facultatives — sans elles, le comportement est
celui de l'original, à ceci près que le certificat est désormais vérifié contre
le magasin du système :

| Option | Défaut | Rôle |
|---|---|---|
| `security` | `"ssl"` | `"ssl"` (TLS implicite) ou `"starttls"` (montée en TLS obligatoire) |
| `port` | 993 / 143 | selon `security` |
| `ca_file` | magasin système | certificat/CA de confiance ; **seul** ce fichier est alors accepté (chemin relatif = relatif à `accounts.toml`) |
| `tls_server_name` | `host` | nom (ou IP) attendu dans le certificat s'il diffère de l'hôte de connexion ; la vérification du nom reste **toujours** active |
| `tls_fingerprint_sha256` | — | empreinte SHA-256 du certificat attendu (hex, `:` acceptés), vérifiée **en plus** de `ca_file` |

Globales (en tête de `accounts.toml`, avant les `[[account]]`) :

| Option | Défaut | Rôle |
|---|---|---|
| `max_body_chars` | 20000 | longueur maximale du corps renvoyé par `get_email` |
| `timeout_seconds` | 30 | délai réseau IMAP |

### Exemple : Proton Bridge, Gmail, Mailo (sans secrets)

```toml
max_body_chars = 20000
timeout_seconds = 30

# Proton Bridge joint par son nom Docker. Son certificat est auto-signé et émis
# pour l'IP 127.0.0.1 : on lui fait confiance explicitement et on vérifie le nom
# contre 127.0.0.1. Les identifiants sont ceux affichés par `info` dans Bridge
# (pas le mot de passe Proton).
[[account]]
key = "proton"
label = "Proton (via Bridge)"
email = "you@proton.me"
host = "proton-bridge"
port = 143
security = "starttls"
ca_file = "/run/secrets/bridge-cert.pem"
tls_server_name = "127.0.0.1"
tls_fingerprint_sha256 = "<EMPREINTE_SHA256_DU_CERTIFICAT_BRIDGE>"   # openssl x509 -in cert.pem -noout -fingerprint -sha256
password_env = "PROTON_BRIDGE_PASSWORD"

# Gmail : mot de passe d'application (2FA requise), magasin de certificats système.
[[account]]
key = "gmail"
label = "Gmail"
email = "you@gmail.com"
host = "imap.gmail.com"
password_env = "GMAIL_APP_PASSWORD"

# Mailo : TLS implicite, magasin de certificats système.
[[account]]
key = "mailo"
label = "Mailo"
email = "you@mailo.com"
host = "mail.mailo.com"
password_env = "MAILO_IMAP_PASSWORD"
```

Récupérer le certificat de Bridge (depuis une machine qui le joint) :

```sh
openssl s_client -starttls imap -connect proton-bridge:143 </dev/null 2>/dev/null \
  | openssl x509 > bridge-cert.pem
openssl x509 -in bridge-cert.pem -noout -fingerprint -sha256
```

Si Bridge est réinitialisé, son certificat change : la connexion est alors refusée
(`tls: certificate verification failed` ou `fingerprint mismatch`) jusqu'à la mise à
jour de `ca_file` / `tls_fingerprint_sha256`. C'est voulu.

### Contenu non fiable

Les sujets, extraits et corps sont écrits par des tiers. Un agent doit les traiter
comme des **données**, jamais comme des instructions. Le serveur ne peut de toute
façon rien modifier, mais il peut lire : ne donnez à l'agent que les comptes
nécessaires.

## Why IMAP

Assistant mail integrations usually connect one Gmail or one Outlook account.
IMAP is the protocol nearly every provider already speaks, so one small server
covers your whole mail footprint with a single read-only code path, no OAuth
apps to register, and nothing granted write access.

## Quickstart

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/otlowan/imap-mcp
cd imap-mcp
cp accounts.example.toml accounts.toml
$EDITOR accounts.toml           # add your accounts
export PERSONAL_IMAP_PASSWORD='...'
uv run imap-mcp                 # starts the MCP server on stdio
```

That's it. Register it with your MCP client (below) and start asking about
your mail.

## Configure accounts

`accounts.toml` is gitignored and holds no secrets:

```toml
[[account]]
key = "personal"                        # short id used in tool calls
label = "you@example.com (Fastmail)"    # optional, defaults to email
email = "you@example.com"               # IMAP login
host = "imap.fastmail.com"
port = 993                              # optional, defaults to 993
password_env = "PERSONAL_IMAP_PASSWORD" # env var holding the password
enabled = true                          # optional, defaults to true
```

Add one `[[account]]` block per mailbox. `enabled = false` keeps an account
listed but never logs into it. Set `IMAP_MCP_ACCOUNTS=/path/to/accounts.toml`
to keep the config outside the repo.

### Provider cheat sheet

| Provider | Host | Password |
|----------|------|----------|
| Gmail / Google Workspace | `imap.gmail.com` | [App password](https://myaccount.google.com/apppasswords) (requires 2FA; the spaces Google shows are stripped automatically) |
| Fastmail | `imap.fastmail.com` | [App password](https://www.fastmail.help/hc/en-us/articles/360058752854) |
| iCloud | `imap.mail.me.com` | [App-specific password](https://support.apple.com/102654) |
| Yahoo | `imap.mail.yahoo.com` | [App password](https://help.yahoo.com/kb/SLN15241.html) |
| Migadu | `imap.migadu.com` | Mailbox password |
| Outlook.com / Microsoft 365 | not supported | Microsoft has retired IMAP basic auth; OAuth is not implemented here |

All standard providers use port 993 (implicit TLS), the default. Mailo:
`mail.mailo.com`. Proton: through Proton Bridge, see [Fork durci](#fork-durci).

### Passwords

Each account's `password_env` names an environment variable that must be set
when the server runs. Any of these work:

```sh
# plain export in the shell that launches your MCP client
export PERSONAL_IMAP_PASSWORD='...'

# direnv, sops, pass, whatever you already use

# 1Password: put op:// references in an env file and wrap the command
op run --env-file=op.env -- uv run imap-mcp
```

## Register with an MCP client

### Claude Code

```sh
claude mcp add imap -- uv run --directory /path/to/imap-mcp imap-mcp
```

Or in `.mcp.json` / your user MCP config:

```json
{
  "mcpServers": {
    "imap": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/imap-mcp", "imap-mcp"]
    }
  }
}
```

### Claude Desktop and other clients

Same command and args in the client's MCP server config
(`claude_desktop_config.json`, etc.). Any stdio MCP client works.

Either way, the password env vars must be visible to the spawned process:
export them in the environment the client launches from, or wrap the command
in your secret injector, e.g. `"command": "op"`,
`"args": ["run", "--env-file=/path/to/op.env", "--", "uv", "run", ...]`.

## Tools

**`list_accounts()`** configured accounts with live status. Run this first;
it tells you which mailboxes are queryable and what to pass as `account`.

```json
{"account": "personal", "email": "you@example.com", "enabled": true, "status": "ok"}
```

**`list_emails(account?, since?, unread_only?, limit?)`** recent mail, newest
first. Omit `account` to merge all enabled accounts into one timeline.

**`search_emails(query, account?, since?, limit?)`** free-text search over
sender, subject, and body. Also cross-account unless you name one.

Both return compact rows:

```json
{"account": "personal", "id": "4711", "from": "billing@hetzner.com",
 "subject": "Invoice 2026-07", "date": "2026-07-03T09:12:44+00:00",
 "unread": true, "list_unsubscribe": false, "snippet": "Your invoice for July...",
 "untrusted_content": true}
```

**`get_email(account, id)`** one full message by the `id` from a row, with
plain-text body preferred (HTML-only mail is converted to text), truncated to
`max_body_chars` (`body_truncated`, `body_chars`). Reading it does not mark it read.

Dates are ISO (`YYYY-MM-DD`); `since` filters everywhere; `limit` applies per
account when merging. If one account is down, its error comes back as a row
and the other accounts still answer.

## Troubleshooting

- **`status: "no-credential"`**: the account's `password_env` variable is not
  set in the server's environment. Remember the server inherits its env from
  whatever launched it (your MCP client), not from your interactive shell.
- **`unreachable: tls: certificate verification failed (...)`**: the server
  certificate is not trusted or not valid for the expected name. For Proton
  Bridge, check `ca_file` and `tls_server_name = "127.0.0.1"`. Never disable
  verification.
- **`status: "unreachable: authentication failed"`** on Gmail/iCloud/Yahoo: you're
  using the account password; these providers require an app password (see
  cheat sheet).
- **Config not found**: the server looks for `accounts.toml` next to
  `pyproject.toml`, or wherever `IMAP_MCP_ACCOUNTS` points. When the package is
  installed (not run from a checkout), always set `IMAP_MCP_ACCOUNTS`.

## Development

```sh
uv run pytest
```

116 tests, no real account: the IMAP layer is faked, and TLS/STARTTLS are
exercised against a local fake IMAP server (`tests/fake_imap.py`) with
throwaway certificates. The suite locks in the read-only contract
(`mark_seen=False`/`BODY.PEEK` on every fetch, `EXAMINE`, the command
allow-list), certificate verification and refusals (untrusted CA, wrong name,
wrong fingerprint, STARTTLS failure without cleartext fallback), input
validation, truncation, the `List-Unsubscribe` flag, and a static check that
**fails if any write IMAP command or TLS weakening appears in the source**.

## License

MIT
