# The Bitting name

The AGPL covers Bitting's code. It says nothing about its name, and it is not supposed to —
no software licence does. This file is the separate thing.

The reason a password manager needs one is narrower than brand protection in the usual
sense. If someone can ship a modified build **called Bitting**, then a user who was told "Bitting
is audited, here is the vault format, here is how to verify a release" has no way to know
whether the thing they installed is that. The name is the only part of the system a user
cannot verify by reading the source. So it is the one part that stays controlled, and
everything else stays free.

## What you may do without asking

**Fork it, modify it, distribute it — commercially or not.** That is the AGPL, and nothing
here narrows it. Take the code anywhere.

**Package unmodified Bitting under the name.** Distribution maintainers — Homebrew, the AUR,
Nixpkgs, Debian, Scoop, anyone — may call it Bitting, provided the source is Bitting's own,
patched only as packaging genuinely requires (build flags, paths, backported fixes, and the
like). You do not need permission and you do not need to ask. See `packaging/` for what is
already maintained here.

**Say what your software is.** "A fork of Bitting." "Compatible with Bitting vaults." "Imports
from Bitting." "Faster than Bitting." Truthful references to Bitting to describe, compare, or
criticise are always fine, and remain fine even if this policy changed tomorrow — that is
nominative use, and trademark law protects it independently of anything written here.

**Write about it.** Documentation, tutorials, reviews, videos, talks, courses. Paid ones
too.

## What needs a different name

**A modified build you distribute to other people.** Change the behaviour, ship it to
users, pick your own name. Chromium and Chrome, Iceweasel and Firefox — this is the
long-established shape of the thing, and it exists because the alternative is a user
believing they are running the audited version when they are not. Modify all you like for
yourself or inside your organisation; the line is distributing under the name.

**Anything that implies this project made or endorsed it.** Naming a product `Bitting Pro`,
`Bitting Cloud`, `Bitting Enterprise`, or `bitting-something`; registering `bitting-*` domains or
package names; using the logo as your own; presenting a hosted service as *the* Bitting
service. If a reasonable person would read it as coming from this project, it needs
permission.

**Certification or audit claims.** Do not state or imply that a build is "verified Bitting",
"Bitting-certified", or has passed a Bitting audit.

## Where the mark actually stands

**"Bitting" is a locksmithing term, not a common word.** It is the pattern of cuts along a
key blade — specifically the code representing those cuts, the thing that lets the right key
be reproduced. Applied to software that stores secrets, it is an *arbitrary* mark: the word
exists, but it has no descriptive relationship to password management, which is the
strongest category of mark short of an invented one.

What was checked before the name was adopted, in August 2026: the whole `bitting-*` crate
namespace was free on crates.io, no Debian or FreeBSD package carries the name, and no
company, product, or project by that name surfaced. The previous name failed exactly these
checks, which is why they now exist as a record rather than an assumption.

**What has not been done: no trademark registration has been filed, and no lawyer has read
this.** Searching the USPTO register directly was attempted and blocked by the site's bot
protection, so the register itself remains unchecked — the absence of a conflict above is
the absence of a *visible* conflict, which is not the same thing.

That is stated plainly rather than left for someone to discover, because this project treats
overclaiming as a bug in the documentation and the same standard applies to a legal notice.
Read this as what the project asks of you and will defend if it can, not as a settled legal
position. If you are making a decision that depends on the strength of the mark, get your
own advice.

## Asking

For anything this file does not clearly permit, open an issue. The default answer for
community and non-commercial use is yes.

---

Copyright (C) 2026 Md Ferdous Alam and Bitting contributors. This policy covers the name
"Bitting" and the Bitting logo only; the software is licensed separately — see `COPYRIGHT`.
