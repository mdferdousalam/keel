/**
 * Keel's window.
 *
 * Two rules shape everything here, and both are about what this file is *not* allowed to
 * have.
 *
 * **It never receives a stored secret.** Every command returns a masked view built in
 * `masking.rs`. There is no code path here that could display a password, because no
 * password ever arrives. When the user asks to copy one, the agent does the copying and
 * sends back a sentence describing what it did.
 *
 * **It never builds DOM from a string.** No `innerHTML`, no `insertAdjacentHTML`, no
 * `new Function`, no template that interpolates a value into markup. Everything is
 * `document.createElement` plus `textContent`. That is more typing and it removes the
 * entire class of bug where an entry title — or worse, text an AI agent wrote — becomes
 * markup. `el()` is the only DOM constructor, so there is one place to audit.
 */

const invoke = window.__TAURI__?.core?.invoke;

/** Poll interval for pending approvals, in milliseconds. */
const APPROVAL_POLL_MS = 700;

/** Poll interval for the lock-state header, in milliseconds. */
const STATUS_POLL_MS = 2000;

const state = {
  status: null,
  entries: [],
  selected: null,
  detail: null,
  tab: "vault",
  query: "",
  health: null,
  activity: null,
  grants: null,
  /** Approval currently on screen, so a poll does not rebuild it under the user. */
  showing: null,
  busy: false,
};

// ---------------------------------------------------------------------------
// DOM construction
// ---------------------------------------------------------------------------

/**
 * Build an element. The only DOM constructor in this file.
 *
 * Children that are strings become text nodes, never markup. That is the whole point: an
 * entry title containing `<script>` is a string here and a string on screen.
 */
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message) {
  const node = document.getElementById("toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => {
    node.hidden = true;
  }, 4000);
}

/** Call a Tauri command, surfacing failures instead of swallowing them. */
async function call(command, args = {}) {
  if (!invoke) throw new Error("this window is not connected to the Keel shell");
  return invoke(command, args);
}

async function guard(fn) {
  if (state.busy) return;
  state.busy = true;
  try {
    await fn();
  } catch (error) {
    toast(String(error));
  } finally {
    state.busy = false;
  }
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function relativeDays(unixSeconds) {
  if (!unixSeconds) return "unknown";
  const days = Math.floor((Date.now() / 1000 - unixSeconds) / 86400);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 60) return `${days} days ago`;
  const months = Math.floor(days / 30);
  if (months < 24) return `${months} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function stamp(unixSeconds) {
  if (!unixSeconds) return "";
  return new Date(unixSeconds * 1000).toISOString().replace("T", " ").replace(/\..*/, "Z");
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function unlockView() {
  const noVault = state.status?.state === "no_vault";
  const passphrase = el("input", {
    type: "password",
    id: "passphrase",
    autocomplete: "current-password",
    placeholder: noVault ? "Choose a master passphrase" : "Master passphrase",
  });
  const confirm = el("input", {
    type: "password",
    autocomplete: "new-password",
    placeholder: "Confirm it",
  });
  const tier = el("select", {}, [
    el("option", { value: "balanced", text: "Balanced — about 1.5s to unlock (recommended)" }),
    el("option", { value: "interactive", text: "Interactive — faster, less resistant" }),
    el("option", { value: "paranoid", text: "Paranoid — several seconds to unlock" }),
  ]);

  const submit = async () => {
    const value = passphrase.value;
    if (!value) return;
    await guard(async () => {
      if (noVault) {
        if (value !== confirm.value) {
          toast("Those do not match. A mistyped passphrase on a new vault locks you out permanently.");
          return;
        }
        await call("create_vault", { passphrase: value, tier: tier.value });
      } else {
        await call("unlock", { passphrase: value });
      }
      // Clear the field immediately. This does not scrub the string from the JS heap —
      // nothing in a webview can — it only shortens how long it is reachable from the DOM.
      passphrase.value = "";
      confirm.value = "";
      await refreshAll();
    });
  };

  const form = el("div", { class: "unlock" }, [
    el("div", { class: "mark", text: "Keel" }),
    el(
      "div",
      { class: "note" },
      noVault
        ? "No vault here yet. Choose a passphrase you can remember and have not used anywhere else — a few unrelated words beat a short complicated one. If you lose it, the vault is gone; there is no recovery."
        : "Unlock to continue."
    ),
    passphrase,
    noVault && confirm,
    noVault && tier,
    el("button", { class: "primary", text: noVault ? "Create vault" : "Unlock", onclick: submit }),
    state.status?.state === "locked" &&
      el("div", { class: "note", text: `Vault: ${state.status.vault_path}` }),
  ]);

  passphrase.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submit();
  });
  setTimeout(() => passphrase.focus(), 0);
  return el("div", { class: "centre" }, form);
}

function header() {
  const status = state.status;
  const locksIn =
    status?.locks_in != null ? `locks in ${Math.max(0, Math.round(status.locks_in))}s` : "";
  return el("header", { class: "bar" }, [
    el("span", { class: "brand", text: "Keel" }),
    el("span", { class: "state", text: status ? `${status.entry_count} · ${locksIn}` : "" }),
    el("span", { class: "spacer" }),
    !status?.hardened &&
      el("span", { class: "state", text: "hardening degraded", title: "See Settings" }),
    el("button", {
      text: "Lock",
      onclick: () => guard(async () => {
        await call("lock");
        await refreshAll();
      }),
    }),
  ]);
}

function tabs() {
  const items = [
    ["vault", "Vault"],
    ["health", "Health"],
    ["activity", "Activity"],
    ["access", "Access"],
    ["settings", "Settings"],
  ];
  return el(
    "nav",
    { class: "tabs" },
    items.map(([id, label]) =>
      el("button", {
        text: label,
        "aria-current": state.tab === id ? "true" : null,
        onclick: () => {
          state.tab = id;
          render();
          loadTab();
        },
      })
    )
  );
}

function entryList() {
  const search = el("input", {
    type: "search",
    placeholder: "Search",
    value: state.query,
    oninput: (event) => {
      state.query = event.target.value;
      guard(async () => {
        state.entries = state.query.trim()
          ? await call("search", { query: state.query })
          : await call("list_entries");
        render();
      });
    },
  });

  const list = el(
    "ul",
    { class: "entries" },
    state.entries.map((entry) =>
      el("li", {}, [
        el(
          "button",
          {
            "aria-current": state.selected === entry.reference ? "true" : null,
            onclick: () =>
              guard(async () => {
                state.selected = entry.reference;
                state.detail = await call("entry_detail", { reference: entry.reference });
                render();
              }),
          },
          [
            el("div", { class: "title", text: entry.title }),
            el("div", { class: "sub", text: entry.username || "no username" }),
          ]
        ),
      ])
    )
  );

  return el("div", { class: "panel stack" }, [
    search,
    state.entries.length === 0
      ? el("div", { class: "note", text: state.query ? "Nothing matches." : "No entries yet." })
      : list,
    el("button", { text: "Add entry", onclick: showAddForm }),
  ]);
}

function detailPanel() {
  if (!state.detail) {
    return el("div", { class: "panel" }, el("div", { class: "note", text: "Select an entry." }));
  }
  const d = state.detail;
  const copy = (field, label) =>
    el("button", {
      text: label,
      onclick: () =>
        guard(async () => {
          const description = await call("copy_field", { reference: d.reference, field });
          toast(description);
        }),
    });

  return el("div", { class: "panel stack" }, [
    el("div", {}, [
      el("div", { class: "title", text: d.title }),
      el("div", { class: "sub", text: d.websites.join(" ") || "no site recorded" }),
    ]),
    el("div", {}, [
      field("Username", el("span", { text: d.username || "—" }), d.username && copy("username", "Copy")),
      field(
        "Password",
        d.password.present
          ? el("span", { class: "mask", text: d.password.bullets })
          : el("span", { class: "muted", text: "none stored" }),
        d.password.present && copy("password", "Copy")
      ),
      d.has_totp && field("One-time code", el("span", { class: "mask", text: "••••••" }), copy("totp", "Copy")),
      field("Password changed", el("span", { text: relativeDays(d.password_changed_at) }), null),
      field("Last edited", el("span", { text: relativeDays(d.updated_at) }), null),
      d.tags.length > 0 &&
        field(
          "Tags",
          el("span", {}, d.tags.map((t) => el("span", { class: "tag", text: t }))),
          null
        ),
    ]),
    el("div", { class: "note" }, [
      "This window never receives a password. Copy puts it on the clipboard and clears it shortly after; ",
      "Show opens a separate native window that is hidden from screen recording. Neither value passes through here.",
    ]),
    el("div", { class: "row" }, [
      el("button", {
        text: "Show on screen",
        onclick: () =>
          guard(async () => {
            await call("reveal_on_screen", { reference: d.reference, field: "password" });
            toast("Opened a window showing it. It closes after 30 seconds, or on any key.");
          }),
      }),
    ]),
    el("div", { class: "row" }, [
      el("button", {
        text: "New password",
        onclick: () =>
          guard(async () => {
            const created = await call("rotate", { reference: d.reference });
            await call("save");
            toast(
              created.strength_bits
                ? `Replaced with a new password, about ${created.strength_bits} bits.`
                : "Replaced with a new password."
            );
            state.detail = await call("entry_detail", { reference: d.reference });
            render();
          }),
      }),
      el("button", {
        class: "danger",
        text: "Move to trash",
        onclick: () =>
          guard(async () => {
            await call("trash", { reference: d.reference });
            await call("save");
            state.detail = null;
            state.selected = null;
            state.entries = await call("list_entries");
            toast("Moved to trash. It can be restored until it is purged.");
            render();
          }),
      }),
    ]),
  ]);
}

function field(label, value, action) {
  return el("div", { class: "field" }, [
    el("div", { class: "label", text: label }),
    value,
    action || el("span"),
  ]);
}

function showAddForm() {
  const title = el("input", { placeholder: "Name, e.g. Chase Bank" });
  const username = el("input", { placeholder: "Username or email" });
  const url = el("input", { placeholder: "https://example.com", inputmode: "url" });
  const words = el("input", { type: "checkbox" });

  state.detail = null;
  state.selected = null;
  const panel = el("div", { class: "panel stack" }, [
    el("div", { class: "title", text: "Add an entry" }),
    title,
    username,
    url,
    el("label", { class: "row" }, [words, el("span", { text: "Use a passphrase instead of characters" })]),
    el("div", {
      class: "note",
      text: "The password is generated in the agent and stored without ever being shown here. Use Copy when you need it.",
    }),
    el("div", { class: "row" }, [
      el("button", {
        class: "primary",
        text: "Create",
        onclick: () =>
          guard(async () => {
            if (!title.value.trim()) {
              toast("An entry needs a name.");
              return;
            }
            const created = await call("add_entry", {
              title: title.value.trim(),
              username: username.value.trim(),
              url: url.value.trim(),
              tags: [],
              length: words.checked ? null : 20,
              words: words.checked ? 6 : null,
            });
            await call("save");
            state.entries = await call("list_entries");
            state.selected = created.reference;
            state.detail = await call("entry_detail", { reference: created.reference });
            toast(
              created.strength_bits
                ? `Added, with a password of about ${created.strength_bits} bits.`
                : "Added."
            );
            render();
          }),
      }),
      el("button", {
        text: "Cancel",
        onclick: () => {
          state.detail = null;
          render();
        },
      }),
    ]),
  ]);
  renderMain(el("div", { class: "split" }, [entryList(), panel]));
  setTimeout(() => title.focus(), 0);
}

function healthView() {
  const h = state.health;
  if (!h) return el("div", { class: "panel", text: "Checking…" });
  const rows = (entries) =>
    entries.map((e) =>
      el("tr", {}, [
        el("td", { text: e.title }),
        el("td", { class: "muted", text: e.username }),
        el("td", { class: "num", text: `~${e.bits} bits` }),
        el("td", {}, el("span", { class: `pill ${e.strength}`, text: e.strength })),
        el("td", { class: "num", text: `${e.age_days}d` }),
      ])
    );
  const table = (entries) =>
    el("div", { class: "scroll-x" }, [
      el("table", {}, [
        el("thead", {}, el("tr", {}, [
          el("th", { text: "Entry" }),
          el("th", { text: "Username" }),
          el("th", { text: "Strength" }),
          el("th", { text: "" }),
          el("th", { text: "Age" }),
        ])),
        el("tbody", {}, rows(entries)),
      ]),
    ]);

  return el("div", { class: "stack" }, [
    h.unreadable > 0 &&
      el("div", {
        class: "banner danger",
        text: `${h.unreadable} record(s) could not be decrypted and are missing from this report. The vault may be damaged; a backup may be available beside it.`,
      }),
    el("div", { class: "panel stack" }, [
      el("div", { class: "title", text: "Vault health" }),
      el("div", {
        class: "note",
        text: `${h.examined} entries examined. ${h.flagged} need attention.${
          h.without_password ? ` ${h.without_password} store no password.` : ""
        }`,
      }),
    ]),
    h.reused.length > 0 &&
      el("div", { class: "panel stack" }, [
        el("div", { class: "title", text: `Reused passwords — ${h.reused.length} group(s)` }),
        el("div", {
          class: "note",
          text: "A password shared between accounts turns any one site's breach into a compromise of all of them. Fix these first.",
        }),
        ...h.reused.map((group) => table(group)),
      ]),
    h.weak.length > 0 &&
      el("div", { class: "panel stack" }, [
        el("div", { class: "title", text: `Weak passwords — ${h.weak.length}` }),
        table(h.weak),
        el("div", {
          class: "note",
          text: "The bit figure is a lower bound from the password's structure, not a guarantee.",
        }),
      ]),
    h.stale.length > 0 &&
      el("div", { class: "panel stack" }, [
        el("div", { class: "title", text: `Unchanged for over a year — ${h.stale.length}` }),
        table(h.stale),
        el("div", {
          class: "note",
          text: "Age alone is not a problem. It matters most for passwords that are also weak or reused.",
        }),
      ]),
    h.flagged === 0 && el("div", { class: "panel", text: "Nothing needs attention." }),
  ]);
}

function activityView() {
  const a = state.activity;
  if (!a) return el("div", { class: "panel", text: "Reading the log…" });
  return el("div", { class: "stack" }, [
    a.suggests_tampering &&
      el("div", {
        class: "banner danger",
        text: `The audit chain does not verify (${a.chain}${
          a.chain_seq ? ` at record ${a.chain_seq}` : ""
        }). Records have been edited, removed, or rewritten. The entries below precede the problem and still verify.`,
      }),
    !a.suggests_tampering &&
      a.chain === "truncated_after" &&
      el("div", {
        class: "banner warn",
        text: "The log ends mid-record. Appends are not atomic, so this is usually an interrupted write rather than interference.",
      }),
    el("div", { class: "panel stack" }, [
      el("div", { class: "title", text: "Recent activity" }),
      el("div", {
        class: "note",
        text: a.suggests_tampering
          ? `Showing ${a.records.length} verified records.`
          : `The hash chain verifies over all ${a.total} records.`,
      }),
      el("div", { class: "scroll-x" }, [
        el("table", {}, [
          el("thead", {}, el("tr", {}, [
            el("th", { text: "#" }),
            el("th", { text: "When" }),
            el("th", { text: "Client" }),
            el("th", { text: "Action" }),
            el("th", { text: "Outcome" }),
          ])),
          el(
            "tbody",
            {},
            [...a.records].reverse().map((r) =>
              el("tr", {}, [
                el("td", { class: "num", text: r.seq }),
                el("td", { class: "num", text: stamp(r.timestamp) }),
                el("td", { text: r.client_id }),
                el("td", { text: r.operation }),
                el("td", {}, el("span", {
                  class: `pill ${r.outcome === "allowed" || r.outcome === "approved_by_user" ? "ok" : "weak"}`,
                  text: r.outcome.replace(/_/g, " "),
                })),
              ])
            )
          ),
        ]),
      ]),
    ]),
  ]);
}

function accessView() {
  const grants = state.grants;
  return el("div", { class: "stack" }, [
    el("div", { class: "panel stack" }, [
      el("div", { class: "title", text: "Connected agents and browsers" }),
      el("div", {
        class: "note",
        text: "Access is granted from the command line with `keel grant`, and can be revoked here at any time. Revoking always works, even mid-request.",
      }),
      !grants || grants.length === 0
        ? el("div", { class: "note", text: "Nothing has been granted access." })
        : el("div", { class: "scroll-x" }, [
            el("table", {}, [
              el("thead", {}, el("tr", {}, [
                el("th", { text: "Client" }),
                el("th", { text: "Can" }),
                el("th", { text: "Covers" }),
                el("th", { text: "Uses left" }),
                el("th", { text: "" }),
              ])),
              el(
                "tbody",
                {},
                grants.map((g) =>
                  el("tr", {}, [
                    el("td", { text: g.client_id }),
                    el("td", { class: "muted", text: g.scopes.join(", ") }),
                    el("td", { class: "muted", text: g.covers }),
                    el("td", { class: "num", text: g.uses_remaining }),
                    el("td", {}, el("button", {
                      class: "danger",
                      text: "Revoke",
                      onclick: () =>
                        guard(async () => {
                          await call("revoke", { client_id: g.client_id });
                          state.grants = await call("grants");
                          toast(`Revoked all access for ${g.client_id}.`);
                          render();
                        }),
                    })),
                  ])
                )
              ),
            ]),
          ]),
    ]),
  ]);
}

function settingsView() {
  const s = state.status;
  return el("div", { class: "stack" }, [
    (s?.warnings?.length ?? 0) > 0 &&
      el("div", { class: "panel stack" }, [
        el("div", { class: "title", text: "Warnings from the agent" }),
        ...s.warnings.map((w) => el("div", { class: "banner warn", text: w })),
      ]),
    el("div", { class: "panel stack" }, [
      el("div", { class: "title", text: "This vault" }),
      field("File", el("span", { class: "muted", text: s?.vault_path ?? "" }), null),
      field("Entries", el("span", { text: s?.entry_count ?? "" }), null),
      field("Agent", el("span", { text: s?.agent_version ?? "" }), null),
      field(
        "Hardening",
        el("span", { text: s?.hardened ? "applied" : "degraded — see warnings" }),
        null
      ),
    ]),
    el("div", { class: "panel stack" }, [
      el("div", { class: "title", text: "What this window can and cannot do" }),
      el("div", { class: "note" }, [
        "This window never receives a password. Entries arrive with their secret fields replaced by bullets, and actions that need the real value are carried out by the agent — the only process holding your keys. ",
        "The one secret that does pass through here is the master passphrase, on its way from the field you type it in to the agent. That is unavoidable in a webview, and it is written down in the threat model rather than glossed over.",
      ]),
    ]),
  ]);
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

/**
 * Render one approval request.
 *
 * Everything shown is ground truth from the agent: the entry title comes from the vault,
 * the client identity from the verified peer. The single exception is `agent_text`, which
 * the requesting client wrote and which may be repeating instructions from a web page. It
 * is set with textContent inside a visually quarantined block, is never a button label, and
 * never becomes part of the app's own chrome.
 */
function renderApproval(item) {
  const host = document.getElementById("approvals");
  if (!item) {
    host.hidden = true;
    host.replaceChildren();
    state.showing = null;
    return;
  }
  if (state.showing === item.approval_id) return; // already up; do not rebuild under the user
  state.showing = item.approval_id;

  const allow = el("button", { class: "primary", text: "Allow once", disabled: true });
  const refuse = el("button", { text: "Refuse" });

  const answer = (approved) =>
    guard(async () => {
      await call("resolve_approval", { approval_id: item.approval_id, approved });
      renderApproval(null);
      await pollApprovals();
    });
  allow.addEventListener("click", () => answer(true));
  refuse.addEventListener("click", () => answer(false));

  // The Allow control stays disabled briefly. A dialog that can be dismissed the instant
  // it appears gets dismissed by a click that was already in flight, and by users who have
  // learned that prompts are noise.
  const armMs = Number(item.arm_delay_ms) || 0;
  if (armMs > 0) {
    const started = Date.now();
    const tick = setInterval(() => {
      const left = Math.ceil((armMs - (Date.now() - started)) / 1000);
      if (left > 0) {
        allow.textContent = `Allow once (${left})`;
      } else {
        allow.textContent = "Allow once";
        allow.disabled = false;
        clearInterval(tick);
      }
    }, 100);
  } else {
    allow.disabled = false;
  }

  const dialog = el("div", { class: "approval" }, [
    el("h2", { text: "A program is asking for a secret" }),
    el("div", {
      class: "note",
      text: `It will time out in ${item.expires_in_secs}s if you do nothing.`,
    }),
    el("dl", {}, [
      el("dt", { text: "Program" }),
      el("dd", { text: `${item.client_id} (${item.client_kind})` }),
      ...(item.executable ? [el("dt", { text: "Running from" }), el("dd", { text: item.executable })] : []),
      el("dt", { text: "Wants to" }),
      el("dd", { text: item.operation.replace(/_/g, " ") }),
      ...(item.entry_title ? [el("dt", { text: "Entry" }), el("dd", { text: item.entry_title })] : []),
      ...(item.destination ? [el("dt", { text: "Destination" }), el("dd", { text: item.destination })] : []),
    ]),
    item.agent_text &&
      el("div", { class: "agent-text" }, [
        el("span", {
          class: "who",
          text: "Text supplied by the program — it may be repeating instructions from a web page or a file it read",
        }),
        el("span", { class: "said", text: item.agent_text }),
      ]),
    el("div", {
      class: "note",
      text: "Allowing this permits one request. The next will ask again.",
    }),
    el("div", { class: "actions" }, [refuse, allow]),
  ]);

  host.replaceChildren(dialog);
  host.hidden = false;
  // Focus lands on Refuse, never on Allow. Enter must not be able to approve anything.
  setTimeout(() => refuse.focus(), 0);
}

async function pollApprovals() {
  if (state.status?.state !== "unlocked") {
    renderApproval(null);
    return;
  }
  try {
    const pending = await call("pending_approvals");
    renderApproval(pending[0] ?? null);
  } catch {
    // A poll failing is not worth a toast every second; the header will show the agent is
    // unreachable soon enough.
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

function renderMain(content) {
  const app = document.getElementById("app");
  app.replaceChildren(header(), tabs(), el("main", {}, content));
}

function render() {
  const app = document.getElementById("app");
  if (!state.status || state.status.state !== "unlocked") {
    app.replaceChildren(unlockView());
    return;
  }
  const body = {
    vault: () => el("div", { class: "split" }, [entryList(), detailPanel()]),
    health: healthView,
    activity: activityView,
    access: accessView,
    settings: settingsView,
  }[state.tab];
  renderMain(body());
}

async function loadTab() {
  await guard(async () => {
    if (state.tab === "health") state.health = await call("health");
    if (state.tab === "activity") state.activity = await call("activity", { limit: 100 });
    if (state.tab === "access") state.grants = await call("grants");
    render();
  });
}

async function refreshAll() {
  state.status = await call("status");
  if (state.status.state === "unlocked") {
    state.entries = await call("list_entries");
  } else {
    // Handles do not survive a lock, so keeping any of this would leave the UI pointing at
    // references the agent has already forgotten.
    state.entries = [];
    state.detail = null;
    state.selected = null;
    state.health = null;
    state.activity = null;
    state.grants = null;
  }
  render();
}

async function start() {
  if (!invoke) {
    document.getElementById("app").replaceChildren(
      el("div", { class: "centre" }, el("div", { class: "panel" }, [
        el("div", { class: "title", text: "Not connected" }),
        el("div", {
          class: "note",
          text: "This page is being viewed outside the Keel application, so it has no way to reach the agent.",
        }),
      ]))
    );
    return;
  }
  try {
    await refreshAll();
  } catch (error) {
    document.getElementById("app").replaceChildren(
      el("div", { class: "centre" }, el("div", { class: "panel stack" }, [
        el("div", { class: "title", text: "Cannot reach the Keel agent" }),
        el("div", { class: "note", text: String(error) }),
        el("button", { class: "primary", text: "Try again", onclick: () => start() }),
      ]))
    );
    return;
  }

  setInterval(() => {
    // Only the header and the approval queue poll. Re-fetching the entry list every couple
    // of seconds would fight the user's scroll position for no benefit.
    guard(async () => {
      const next = await call("status");
      const wasUnlocked = state.status?.state === "unlocked";
      state.status = next;
      if (wasUnlocked !== (next.state === "unlocked")) {
        await refreshAll();
      } else if (state.tab === "vault" || state.tab === "settings") {
        render();
      }
    });
  }, STATUS_POLL_MS);

  setInterval(pollApprovals, APPROVAL_POLL_MS);
}

start();
