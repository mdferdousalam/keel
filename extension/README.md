# The Keel browser extension

Loaded unpacked during development:

1. Run `keel setup-browser` once. It writes the native-messaging manifests that let a
   browser launch `keel-native-host`, and prints where it put them.
2. Open `chrome://extensions`, turn on Developer mode, choose **Load unpacked**, and select
   this directory.
3. Copy the extension ID Chrome assigns and re-run `keel setup-browser --extension-id <ID>`,
   so the native-messaging manifest lists your build rather than the published one.

That last step matters: `allowed_origins` in the native-messaging manifest is what stops an
*arbitrary* extension from launching the host. It is necessary and, as the threat model
says, not sufficient — any process running as you can execute the host directly, which is
why the agent decides everything and the host decides nothing.

## What is deliberately absent

**No `<all_urls>`, and no declarative content scripts.** Nothing is injected until you click
the toolbar button. The trade is real: Keel cannot detect a login form and offer to fill it
as the page loads. That automatic behaviour is the root of most extension credential-leak
CVEs, because it means untrusted page content is being parsed by privileged code on every
site you visit. Clicking is a small price.

**No third-party JavaScript.** Plain ES modules, no bundler, no npm. The same reasoning as
the desktop window: a build step is a supply chain, and this code sits between a page and
your passwords.

**Nothing secret in `storage.local`.** That store is a plaintext LevelDB in the browser
profile. The extension keeps no passwords, no vault metadata, and no key material — it holds
opaque per-session handles that stop resolving the moment the vault locks.

**No pairing yet.** The plan calls for a SAS pairing flow and a Noise channel between the
extension and the agent. Not built. Its value would be against a same-user process
impersonating the browser, which is outside the threat model the rest of Keel is written
against — but it is a real gap and is recorded as one rather than quietly skipped.
