# Blind Handoff

Threat Model Lab · Exercise 2. A deliberately hackable classroom web app for teaching **identity, authorization, and audit-log forensics**. One shared public repo; students attack it, patch it, and read the logs to catch each other.

## Run it

```
node server.js
```

Then open http://localhost:3000. No dependencies, Node 16+. To reset the game, delete `data.json` and `groundtruth.log` and restart.

Set a different port with `PORT=8080 node server.js`. To let others on the classroom network reach it, run it on one machine and share that machine's LAN address (e.g. `http://192.168.1.20:3000`).

## Accounts (defaults)

All player accounts ship with the password **`changeme`** (reused weak passwords are part of the attack surface — students should change them, and attackers will guess the ones who didn't).

- **Blue:** `maya_b`, `leo_b`, `ava_b`, `sam_b`
- **Red:** `dev_r`, `nia_r`, `kai_r`, `zoe_r`
- **Instructor:** `instructor` / `instructor`

Edit the `seed()` function in `server.js` (or `data.json`) to match your roster.

## How a day works

1. Instructor opens the panel (log in as `instructor`) and clicks **Start new day** — the server randomly names one member of the defending team the **Source** and gives them custody of the secret.
2. Players **pass** custody to teammates from their dashboard. The goal is for every real member to hold it and no attacker to.
3. The **Source** — and only the Source — can delete entries from the audit log.
4. The instructor's **ground-truth log** (`/admin/truth`) records everything, including deletions players can't see, and is the authority for scoring.

## Scoring (adjudicated by the instructor via the panel)

- **Availability:** Blue +1 if every member has been passed the secret.
- **Infiltration:** Red +2 if any Red account gained custody; if none did, Blue +2 — *but only if Blue also passed to every member.*
- **Detection** (only if Red infiltrated): Blue +1 for identifying it happened, +2 more for correctly naming the account; Red +1 if Blue identifies neither.
- **Vulnerability discovered:** +4 to the first team to document a real vuln with a working reproduction.
- **Patch accepted:** +2 for a merged fix (fixer need not be the finder).

The panel auto-flags when an attacker account holds the secret and gives you quick point entry.

## Intentional weaknesses (the attack surface)

These are **on purpose**. They are marked `>>> WEAKNESS` in `server.js`. Finding, exploiting, and patching them is the game.

| # | Weakness | Enables | A fix might be… |
|---|----------|---------|-----------------|
| 1 | All players share the default password `changeme` | Credential guessing / reuse | Enforce a password change on first login; block weak passwords |
| 2 | Password change requires no reauthentication | Account takeover from an unlocked device | Require the current password (or a fresh login) to change it |
| 3 | Session cookie has no `HttpOnly`/`Secure`/`SameSite` and never expires | Cookie theft, session sharing, stay-logged-in-forever | Add the flags; expire idle sessions |
| 4 | Custody can be passed to *any* account, no roster check | Social-engineered / mistaken handoffs to attackers | Restrict recipients to the holder's team roster |
| 5 | The Source can delete log entries, leaving no in-app trace | Covering tracks / repudiation | Make the in-app log append-only, or log every edit visibly |
| 6 | Laptop-only rule is a crude, spoofable User-Agent check | Bypass by faking a desktop UA | (Advanced) bind sessions more strongly to a device |
| 7 | Inbox renders pasted links as clickable | In-app phishing (email/social vectors) | Warn on external links; strip or sandbox them |

Phishing itself (cloning the login page, tab-napping, social engineering) is not "in" the code — the login page is deliberately plain and self-contained so students can clone it. The instructor's ground-truth log is the backstop that always reveals what really happened.

## Structure of the code

`server.js` is one file, top to bottom: data store → logging → HTTP helpers → identity → page layout → login page → router → player pages → instructor pages. It is meant to be read in an afternoon and patched via pull request to the shared repo.
