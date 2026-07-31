// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md

/**
 * The Keel extension's service worker.
 *
 * It owns the one privileged capability the extension has — the native-messaging port to
 * `keel-native-host` — and does as little as possible with it.
 *
 * Two things are worth stating because they are easy to get wrong and expensive when wrong.
 *
 * **The origin always comes from the browser.** Every message that names an origin gets it
 * from `tab.url`, which the browser sets, never from anything a page reported about itself.
 * A page can say whatever it likes about its own address; `location.href` and
 * `document.domain` are attacker-controlled on an attacker's page.
 *
 * **Nothing here decides whether a fill is allowed.** The agent re-parses the origin and
 * checks it against the entry's own stored origins. This worker could not authorise a fill
 * if it wanted to, which is the point: it runs in a browser process, next to hostile input,
 * and the vault is on the other side of a socket that answers only specific questions.
 */

/** Name registered in the native-messaging manifest that `keel setup-browser` writes. */
const HOST = "dev.keel.native_host";

let nextId = 1;

/**
 * Send one message to the native host and await its reply.
 *
 * A fresh connection per message. Chrome's `sendNativeMessage` does exactly that, and it
 * suits this design: the host is a stateless pipe, so there is no session to keep, and a
 * short-lived process is one less thing holding a credential in memory.
 */
function ask(message) {
  return new Promise((resolve) => {
    const payload = { id: nextId++, ...message };
    try {
      chrome.runtime.sendNativeMessage(HOST, payload, (reply) => {
        const error = chrome.runtime.lastError;
        if (error) {
          // The usual cause is that `keel setup-browser` has not been run, so the browser
          // has no manifest telling it how to launch the host.
          resolve({
            ok: false,
            code: "host_unavailable",
            error:
              "Keel's browser bridge is not installed. Run `keel setup-browser` and reload the extension.",
          });
          return;
        }
        resolve(reply ?? { ok: false, code: "no_reply", error: "The bridge sent no reply." });
      });
    } catch (e) {
      resolve({ ok: false, code: "host_unavailable", error: String(e) });
    }
  });
}

/** The active tab, and the origin the browser says it has. */
async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return { tab: null, origin: null };
  let origin = null;
  try {
    const url = new URL(tab.url);
    // Only pages a password could belong to. `chrome://`, `about:`, `file:` and extension
    // pages are not places to fill a credential, and the agent would refuse them anyway —
    // failing here keeps the popup honest about why.
    if (url.protocol === "https:" || url.protocol === "http:") {
      origin = url.origin;
    }
  } catch {
    origin = null;
  }
  return { tab, origin };
}

/**
 * Fill a credential into the active tab.
 *
 * Injected on demand with `chrome.scripting.executeScript` rather than by a declarative
 * content script, so nothing of Keel's runs on a page until the user clicks. The injected
 * function re-checks the origin as its first act: between the popup asking and this running,
 * the page may have navigated, and writing a password into wherever it went would be exactly
 * the bug this whole path is arranged to avoid.
 */
async function fillActiveTab(tabId, expectedOrigin, credential) {
  const [result] = await chrome.scripting.executeScript({
    target: { tabId, allFrames: false },
    // The isolated world, never MAIN. In MAIN the page could redefine the DOM functions this
    // code calls and read the value as it is written.
    world: "ISOLATED",
    args: [expectedOrigin, credential.username, credential.password],
    func: (expectedOrigin, username, password) => {
      // 1. Ground truth, re-checked here rather than trusted from the message.
      if (window.location.origin !== expectedOrigin) {
        return { ok: false, reason: "the page navigated before the password could be filled" };
      }
      if (window.top !== window) {
        return { ok: false, reason: "refusing to fill inside a frame" };
      }

      const visible = (el) => {
        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);
        return (
          rect.width > 1 &&
          rect.height > 1 &&
          style.visibility !== "hidden" &&
          style.display !== "none" &&
          Number(style.opacity) > 0.1
        );
      };

      const usable = (el) =>
        el && !el.disabled && !el.readOnly && visible(el);

      // 2. Find the fields. A password input that is `type="text"` is refused rather than
      //    filled: it may be a harvesting field styled to look inert, and the user would not
      //    see the value appear as dots.
      const passwordField = [...document.querySelectorAll('input[type="password"]')].find(usable);
      if (!passwordField) {
        const masquerading = document.querySelector(
          'input[name*="pass" i], input[id*="pass" i]'
        );
        return {
          ok: false,
          reason: masquerading
            ? "the password field on this page is not a real password field, so Keel will not fill it"
            : "no password field found on this page",
        };
      }

      // 3. A form that posts somewhere else is worth refusing over. This is the shape of a
      //    credential-forwarding page.
      const form = passwordField.form;
      if (form && form.action) {
        try {
          const target = new URL(form.action, window.location.href);
          if (target.origin !== window.location.origin) {
            return {
              ok: false,
              reason: `this form submits to ${target.origin}, not ${window.location.origin}`,
            };
          }
        } catch {
          /* A form action that will not parse is left alone; the browser will not post it. */
        }
      }

      const setValue = (el, value) => {
        el.focus();
        // Set through the native setter so frameworks observing the property still see it.
        const setter = Object.getOwnPropertyDescriptor(
          window.HTMLInputElement.prototype,
          "value"
        )?.set;
        if (setter) setter.call(el, value);
        else el.value = value;
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
      };

      // 4. Username first, if there is somewhere sensible to put it.
      if (username) {
        const candidates = [
          ...document.querySelectorAll(
            'input[type="email"], input[type="text"], input[type="tel"], input:not([type])'
          ),
        ].filter(usable);
        // The one immediately before the password field is the login field on essentially
        // every form; picking the first text input on the page would sometimes fill a search
        // box instead.
        const all = [...document.querySelectorAll("input")];
        const passwordIndex = all.indexOf(passwordField);
        const before = candidates
          .filter((el) => all.indexOf(el) < passwordIndex)
          .pop();
        if (before) setValue(before, username);
      }

      setValue(passwordField, password);
      return { ok: true };
    },
  });
  return result?.result ?? { ok: false, reason: "the page could not be reached" };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  // Everything here is async, so the listener returns true to keep the channel open.
  (async () => {
    switch (message?.type) {
      case "state": {
        const { tab, origin } = await activeTab();
        if (!origin) {
          sendResponse({ ok: true, result: { origin: null, entries: [], state: null } });
          return;
        }
        const status = await ask({ type: "status" });
        if (!status.ok) {
          sendResponse(status);
          return;
        }
        if (status.result?.state !== "unlocked") {
          sendResponse({ ok: true, result: { origin, state: status.result?.state, entries: [] } });
          return;
        }
        const candidates = await ask({ type: "candidates", origin });
        sendResponse({
          ok: candidates.ok,
          code: candidates.code,
          error: candidates.error,
          result: {
            origin,
            tabId: tab?.id ?? null,
            state: "unlocked",
            entries: candidates.result?.entries ?? [],
          },
        });
        return;
      }

      case "fill": {
        // Re-resolved rather than taken from the popup's message, so the origin filled into
        // is the one the browser reports *now*.
        const { tab, origin } = await activeTab();
        if (!tab || !origin) {
          sendResponse({ ok: false, error: "This page cannot be filled." });
          return;
        }
        const credential = await ask({ type: "fill", reference: message.reference, origin });
        if (!credential.ok) {
          sendResponse(credential);
          return;
        }
        // The agent echoes the origin it verified. If it disagrees with what the browser says
        // now, something changed mid-flight and nothing should be written.
        if (credential.result?.origin && credential.result.origin !== stripDefaultPort(origin)) {
          sendResponse({
            ok: false,
            error: "The page changed while Keel was fetching the password. Nothing was filled.",
          });
          return;
        }
        const outcome = await fillActiveTab(tab.id, origin, credential.result);
        sendResponse(
          outcome.ok
            ? { ok: true, result: { filled: true } }
            : { ok: false, error: outcome.reason }
        );
        return;
      }

      default:
        sendResponse({ ok: false, error: "unknown request" });
    }
  })();
  return true;
});

/**
 * Drop an explicit default port, so a browser origin and the agent's canonical form compare
 * equal. Chrome omits the default port in `URL.origin` already; this guards the case where a
 * URL carried `:443` explicitly.
 */
function stripDefaultPort(origin) {
  return origin.replace(/^https:\/\/([^/]+):443$/, "https://$1").replace(/^http:\/\/([^/]+):80$/, "http://$1");
}
