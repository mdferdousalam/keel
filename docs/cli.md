# The `bitting` command

## How it works

`bitting` is a thin client. The vault is held by a background process, `bitting-agent`, which is
started automatically the first time you run a command and holds the unlocked vault so you
unlock once per session rather than once per command.

That split is a security decision as much as a convenience one: the agent is the only
process that ever holds key material, so "which code can read my passwords?" has a
one-binary answer. `bitting` itself cannot decrypt anything — it has no access to the
cryptographic code at all, and a CI check enforces that.

```
bitting  ──unix socket──►  bitting-agent  ──►  vault.bitting
```

## Secret-handling rules

These are not stylistic choices. Each closes a specific hole:

**No secret is ever accepted as a command-line argument.** There is deliberately no
`--password VALUE` flag. Arguments are visible to every process on the machine through `ps`,
and they persist in shell history long after the session. Secrets arrive by prompt, by
stdin, or from a file you control.

**`bitting get` copies rather than prints.** A password on a terminal survives in scrollback,
in screen recordings, and in the memory of whoever walked past. Printing requires `--show`.

**Exit codes are stable**, so a script can branch on the outcome without parsing prose:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General failure |
| 2 | The vault is locked |
| 3 | No such entry |
| 4 | Refused by policy, or a rate limit |

## Commands

```
bitting init [--tier interactive|balanced|paranoid]
bitting unlock [--accept-rollback]
bitting lock
bitting status
bitting list [--limit N]
bitting search <query>
bitting add <title> [--username U] [--url URL]... [--tag T]...
                 [--password-stdin | --length N | --words N]
bitting get <name> [--field password|username|totp|notes] [--show]
bitting rotate <name> [--length N | --words N]
bitting rm <name> [--yes]
bitting generate [--length N | --words N]
bitting save
```

Every command accepts `--json` for machine-readable output.

### Creating a vault

```sh
bitting init
```

Prompts twice for a new master passphrase. The confirmation matters more here than anywhere
else: a mistyped passphrase on an *existing* vault is an error message, but a mistyped
passphrase on a *new* vault locks you out of everything you subsequently store, permanently
and silently.

`--tier` controls key-derivation cost. `balanced` (the default) uses 512 MiB and takes
roughly one to two seconds; `interactive` uses 256 MiB and is faster; `paranoid` uses 1 GiB.
Because the agent holds the vault open, you pay this once per session, not per command.

### Adding entries

By default the password is **generated** and never displayed:

```sh
$ bitting add "Example Bank" --username ada@example.com --url https://bank.example.com
Added Example Bank (129 bits of entropy).
```

The value is created inside the agent and stored without crossing back, so nothing that
could log it ever sees it. To store a password you already have:

```sh
printf '%s' "$EXISTING" | bitting add "Old Forum" --username ada --password-stdin
```

For a passphrase instead of a character password:

```sh
bitting add "Router" --words 6
```

### Retrieving

```sh
bitting get "Example Bank"          # applies the secret; does not print it
bitting get "Example Bank" --show   # prints it
bitting get "Example Bank" --field totp
```

An ambiguous name is refused rather than guessed:

```sh
$ bitting get Bank --show
bitting: "Bank" matches 2 entries (Bank One, Bank Two); be more specific
```

Guessing would risk acting on the wrong entry — and for `bitting rotate`, that means changing a
password the user never meant to touch.

### Rotating

```sh
bitting rotate "Example Bank"
```

Replaces the password with a fresh one and keeps the previous value in history. History
exists because rotation without it causes lockouts: a site that silently rejected the new
password would otherwise leave you with no way back.

### Deleting

```sh
bitting rm "Old Forum"
```

Moves the entry to the trash rather than destroying it. There is no hard-delete command,
because an accidental permanent deletion in a password manager can lock someone out of an
account for good.

## Automation

Two supported ways to run without a terminal.

**A passphrase file** — the recommended one:

```sh
printf '%s' "$PASSPHRASE" > ~/.bitting-pass
chmod 600 ~/.bitting-pass
export BITTING_PASSPHRASE_FILE=~/.bitting-pass
bitting unlock
```

Bitting **refuses** a passphrase file that other users can read, rather than warning about it. A
passphrase the whole machine can read defeats the vault entirely, and a warning in a script's
output is a warning nobody sees.

**Piped stdin**, when stdin is not a terminal:

```sh
printf '%s' "$PASSPHRASE" | bitting unlock
```

Note what is *not* offered: an environment variable holding the passphrase itself.
Environment variables are readable through `/proc/<pid>/environ` by anything running as the
same user, are inherited by every child process, and end up verbatim in CI logs. A file at
least has permissions.

## Environment variables

| Variable | Purpose |
|---|---|
| `BITTING_VAULT` | Vault file path. Defaults to the platform data directory. |
| `BITTING_PASSPHRASE_FILE` | File holding the master passphrase, mode 600. |
| `BITTING_AGENT_SOCKET` | Agent socket path. Useful for running two vaults side by side. |
| `BITTING_AGENT_BINARY` | Path to `bitting-agent`, for unusual installs. |
| `BITTING_AGENT_IDLE_EXIT_SECS` | How long an idle, locked agent lingers. Default 900. |

## Scripting

```sh
# List entries as JSON
bitting --json list | jq -r '.entries[].title'

# Branch on lock state
if ! bitting status --json | jq -e '.state == "Unlocked"' >/dev/null; then
  bitting unlock
fi

# Distinguish "locked" from "missing"
bitting get "Some Site" --show
case $? in
  0) ;;
  2) echo "vault is locked" ;;
  3) echo "no such entry" ;;
esac
```

## The agent

Starts on demand and exits after 15 minutes idle with the vault locked. It locks itself
after 5 minutes of inactivity, and after 8 hours regardless of activity.

```sh
bitting status          # includes when it will lock
bitting lock            # lock now
```

Repeated wrong passphrases cause an increasing delay, capped at a minute. They never lock you
out permanently and there is no counter that destroys a vault: an attacker holding the file
runs Argon2 offline at whatever rate they like and never touches this code path, so a
destructive counter would punish only the user who mistyped.

## What is not built yet

Being explicit so nothing here is mistaken for a bug:

- `bitting get` without `--show` reports that it needs the desktop app. Clipboard and synthetic
  typing need platform integration that ships with the GUI. It fails loudly rather than
  claiming to have copied something — a user who believes a password was copied and then
  pastes stale clipboard contents into a login form has been actively misled.
- `bitting import`, `bitting export`, and `bitting audit` are not implemented.
- Windows is not supported yet: the agent needs a named-pipe transport with a
  current-user-only DACL, and that is not written.
