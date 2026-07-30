# Giving an AI agent access to your vault

Keel can expose your vault to an AI agent through the Model Context Protocol. This document
explains what an agent can and cannot do, and why.

## The claim

> In the shipped configuration an agent can log you into things and manage entries, and
> **cannot exfiltrate a single password — even if it is entirely controlled by an attacker.**

That is a strong claim, so here is exactly what makes it true, and where it stops being true.

## Why an agent almost never needs to see a password

The insight the whole design rests on: an agent does not need to *read* your password, it needs
your password to be *used*.

So the tool an agent should reach for is `use_secret`. Keel applies the password itself —
copying it, or typing it — and returns only a status. The plaintext never reaches the model, so
it never reaches the model's context, its logs, or whatever the model was tricked into sending
it to.

`reveal_secret`, the one tool that returns plaintext, is **disabled by default** for AI agents.
When you turn it on, every single request still needs your approval in the Keel window, with
the entry and destination shown as Keel knows them rather than as the agent described them.

## Setting it up

```json
{
  "mcpServers": {
    "keel": {
      "command": "keel-mcp",
      "env": { "KEEL_MCP_CLIENT_ID": "claude-code" }
    }
  }
}
```

Set `KEEL_MCP_CLIENT_ID` to something recognisable. It appears in approval prompts and in the
audit log, and "claude-code wants your password" is far more useful to you than "an AI agent
wants your password".

An agent starts with **no access at all**. You grant it explicitly:

```sh
# Metadata and use, limited to work entries, for half an hour
keel grant claude-code --scope metadata --scope use --tag 'work/*' --minutes 30

keel grants            # what is currently granted
keel revoke claude-code
```

Grants expire, and they die when the vault locks. There is no permanent grant.

## What an agent can do

| Tool | What it does |
|---|---|
| `vault_status` | Check whether the vault is unlocked. Needs no permission. |
| `search_entries` | Find entries by title, username, or site. Metadata only. |
| `get_entry_metadata` | Read one entry's non-secret fields. |
| `use_secret` | **Apply** a password without receiving it. |
| `reveal_secret` | Receive plaintext. Off by default; needs your approval each time. |
| `generate_password` | Generate a password. Needs no vault access. |
| `create_entry` | Create an entry, with a password Keel generates and does not disclose. |
| `rotate_secret` | Replace a password. The old one is kept in history. |
| `update_entry` | Change non-secret fields. |
| `trash_entry` | Move to the trash. Reversible. |

## What an agent cannot do, at any permission level

There is no tool for any of these, and adding one would be a design change rather than a
feature:

- **Export or enumerate the vault.** No `export_vault`, no `list_all_entries`. Search needs at
  least two characters and returns a bounded page, so an agent cannot walk the alphabet to
  discover what you have.
- **Unlock the vault or change your master passphrase.** An agent that could unlock a vault can
  be tricked into unlocking it.
- **Delete anything permanently.** `trash_entry` is reversible; there is no purge.
- **Read files, run commands, or find out where your vault lives.**

## Defending against a compromised agent

An agent that read a malicious web page is an attacker holding a legitimate session. That is not
hypothetical, so the design assumes it:

**No enumeration.** Covered above. There is additionally a cap on how many *distinct* entries
one client may touch per hour, so patiently working through the vault one entry at a time trips
the limit too.

**Agent text is data, never instructions.** Anything an agent writes — the `reason` on a reveal
request — is stripped of control characters, escape sequences, bidirectional overrides, and
zero-width characters, truncated, and shown as inert plain text in a box labelled as coming from
the agent. It is never styled as though Keel were saying it. An agent cannot make a prompt look
like a system message.

**Approval prompts show ground truth.** The entry title and the destination come from the vault
and from Keel's own resolution, never from the agent's description. An agent cannot say "this is
for github.com" while the password goes elsewhere. The confirm button is also unarmed for a
moment, so a prompt cannot be dismissed reflexively or clicked by a synthetic event.

**A circuit breaker.** Repeated refusals revoke everything for that client and require a fresh
unlock. An agent scripting its way through variations to find an unguarded path ends its session
instead of continuing.

**Everything is logged.** A hash-chained audit log records what was asked and what was decided,
including refusals — which are the entries worth having afterwards. It records entry
identifiers, never titles or secrets.

## Where the claim stops

Being honest about the boundary, because a claim without one is marketing:

- **If you enable `reveal_secret` and approve a request, the agent gets the password.** That is
  what approving means. The protections are there to make sure you know what you are approving,
  not to override you.
- **If you approve everything without reading it, none of this helps.** The unarmed button and
  the default-deny focus fight approval fatigue; they cannot cure it.
- **A grant covering every entry is a grant covering every entry.** `--tag` exists for a reason,
  and `--all-entries` is deliberately explicit rather than the default.
- **This says nothing about the agent's own security.** A compromised agent with `use_secret`
  can still log *itself* into your accounts. That is precisely why grants are narrow and
  short-lived, and why `keel revoke` exists.

## Recommended configuration

Grant `metadata` and `use`. Leave `reveal` off.

An agent so configured can find your login, log you in, create entries with strong generated
passwords, and rotate old ones — everything most people actually want from this — while a total
compromise of that agent yields no passwords at all.
