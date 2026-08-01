# Bitting additional permission — application distribution services

*Additional permission under section 7 of the GNU Affero General Public License,
version 3.*

## Why this exists

Bitting is licensed under AGPL-3.0-or-later. That license forbids conveying the program
under terms that add restrictions to the ones it grants — and the terms of service of
every major mobile application store do exactly that. Apple's App Store terms limit how
many devices a copy may be installed on and forbid the recipient from redistributing it,
neither of which the AGPL permits a distributor to impose. This is not a theoretical
conflict: it is why VLC was removed from the App Store in 2011.

The consequence, without this file, is that Bitting could never ship an iOS application.
macOS has other channels — Bitting already distributes a notarized `.dmg` and a Homebrew
formula, see `packaging/` — but on iOS the App Store is the only channel that exists.

So the copyright holders grant the permission below. Section 7 of the AGPL exists
precisely so that a copyright holder can make this kind of allowance deliberately, rather
than everyone quietly ignoring the conflict.

## The permission

As an additional permission under section 7 of the GNU Affero General Public License
version 3, the copyright holders of Bitting grant you permission to convey a covered work,
in object-code form only, through an **application distribution service** — an operator
that distributes applications to end users and requires, as a condition of that
distribution, acceptance of terms that would otherwise be forbidden by section 10 of the
License — notwithstanding those terms, and notwithstanding section 6's requirement that
you not impose further restrictions to the extent that the operator's terms impose them
on the copy so distributed.

This permission is granted **only** on all of the following conditions.

1. **The source stays available to everyone, not just to the store's customers.** The
   Corresponding Source for the exact version you convey is made publicly available at no
   charge, under AGPL-3.0-or-later, through a network server that any member of the public
   may reach — not only the people who obtained the binary from the store, and not on
   request. Naming the location in the application's about screen or store listing is
   required.

2. **Section 13 is not waived.** If the work is modified to interact with users remotely
   through a computer network, the obligation in section 13 to offer those users the
   Corresponding Source continues to apply in full.

3. **Anti-Tivoization is not waived beyond the store's own requirements.** Where section 6
   requires Installation Information for a User Product, that requirement continues to
   apply to every channel other than the application distribution service itself. You may
   not rely on this permission to lock a user out of a device you otherwise control.

4. **No sublicensing of the restrictions.** This permission lets you *accept* an
   operator's restrictive terms in order to distribute through it. It does not let you
   impose restrictions of your own, add terms to the source, apply digital restrictions
   beyond what the operator technically requires, or convey the work under any license
   other than AGPL-3.0-or-later plus this permission.

5. **It travels with the source.** Anyone who receives the Corresponding Source receives
   it under AGPL-3.0-or-later together with this same permission, so the next person can
   ship to a store too. Nobody gets a private key to the only viable mobile channel.

If you convey the work in a way that breaches any of these conditions, this additional
permission does not apply to that act of conveying, and the License applies unmodified.

## Notes on scope

**This is a permission, not a restriction.** As section 7 provides, you may remove this
additional permission from any copy you convey, or from any part of it. Removing it leaves
you with plain AGPL-3.0-or-later, which is a valid choice — it simply means you cannot use
an app store.

**It does not weaken the copyleft.** The source obligation is untouched, and condition 1
makes it stricter than the AGPL alone requires: public availability, not merely
availability to the people who received a binary. Whatever an app store's terms say about
its own customers, the source of every shipped Bitting build remains public and remains AGPL.

**It does not apply to the permissively licensed crates.** `crates/bitting-proto`
(Apache-2.0) and `crates/bitting-client` (MPL-2.0) are not covered by the AGPL and need no
exception; those licenses have no conflict with any store's terms.

**Contributions inherit it.** Contributions are accepted under the Developer Certificate
of Origin, with no copyright assignment — so a permission like this one can only be
granted by every copyright holder. To keep it effective as the contributor list grows,
`CONTRIBUTING.md` records that contributions are made under AGPL-3.0-or-later *together
with* this additional permission. A contributor who is unwilling to grant it should say so
in the pull request rather than sign off.

## Header text

Source files in the AGPL portion of the tree carry:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission for app-store distribution: see LICENSE-EXCEPTION.md
```

The `LicenseRef` form is deliberately avoided: the SPDX identifier stays plain
`AGPL-3.0-or-later` so that `cargo-deny`, crates.io, and downstream license scanners read
the crate correctly, since an additional *permission* never makes a license more
restrictive than the identifier claims.
