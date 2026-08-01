// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

/**
 * The Bitting popup.
 *
 * The list of entries offered here is the *only* place a credential can be chosen, and a
 * click here is the only thing that causes one to be fetched. That is the gesture gate: the
 * popup is browser chrome, so a page cannot overlay it, read it, or synthesise a click in it.
 *
 * Built with `createElement` and `textContent`, never `innerHTML`. Entry titles and usernames
 * come from the vault, but they were typed by a user or imported from a CSV, and treating
 * them as markup in a privileged extension page would be a needless hole.
 */

const root = document.getElementById("root");

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, String(value));
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
  return node;
}

const send = (message) =>
  new Promise((resolve) => chrome.runtime.sendMessage(message, resolve));

function shell(originLabel, body) {
  root.replaceChildren(
    el("header", {}, [
      el("span", { class: "brand", text: "Bitting" }),
      el("span", { class: "origin", text: originLabel ?? "" }),
    ]),
    body
  );
}

function message(text, extra) {
  return el("div", { class: "pad" }, [el("div", { class: "note", text }), extra]);
}

async function render() {
  shell(null, message("Checking…"));
  const reply = await send({ type: "state" });

  if (!reply?.ok) {
    shell(
      null,
      message(
        reply?.error ?? "Bitting could not be reached.",
        reply?.code === "host_unavailable"
          ? el("div", { class: "note", text: "Run `bitting setup-browser`, then reload this extension." })
          : null
      )
    );
    return;
  }

  const { origin, state, entries, tabId } = reply.result;

  if (!origin) {
    shell(null, message("Bitting only fills passwords on http and https pages."));
    return;
  }
  if (state !== "unlocked") {
    shell(
      origin,
      message(
        state === "no_vault"
          ? "No Bitting vault on this machine yet. Open Bitting to create one."
          : "Your vault is locked. Open Bitting and unlock it.",
        // Deliberately not a button that unlocks. A page can cause this popup's data to be
        // fetched, and an unlock prompt reachable from page activity is a phishing primitive.
        el("div", { class: "note", text: "Bitting will not ask for your passphrase here." })
      )
    );
    return;
  }
  if (entries.length === 0) {
    shell(origin, message(`No saved entry lists ${origin}.`));
    return;
  }

  const list = el(
    "ul",
    {},
    entries.map((entry) =>
      el("li", {}, [
        el(
          "button",
          {
            class: "entry",
            onclick: async (event) => {
              // Belt and braces: only a real click, never a synthesised one. The popup is
              // not reachable from a page, so this is defence in depth rather than the
              // primary control.
              if (!event.isTrusted) return;
              event.currentTarget.disabled = true;
              const outcome = await send({ type: "fill", reference: entry.reference, tabId });
              if (outcome?.ok) {
                window.close();
              } else {
                shell(origin, message(outcome?.error ?? "Bitting could not fill this page."));
              }
            },
          },
          [
            el("div", { class: "title", text: entry.title }),
            el("div", { class: "sub", text: entry.username || "no username" }),
          ]
        ),
      ])
    )
  );

  shell(origin, el("div", {}, [list, el("div", { class: "note pad", text: "Click an entry to fill this page." })]));
}

render();
