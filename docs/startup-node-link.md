# Startup card / default group linkage

The WebUI links only the group named by the **last `MATCH,<target>` rule**.
It does not guess by group name or update unrelated groups.

- `POST /nodes/selection`: validate the concrete AnyTLS node, change the default
  group's `selected` and `config.yaml.selected` in the existing profile
  transaction. A same-node request repairs a mismatching group.
- `POST /groups/selection`: if this is the default group and the choice is a
  concrete node, update the startup selection in the same transaction, including
  a same-choice repair. Dedicated groups remain independent.
- Missing membership, unsupported select-group edits, and a currently nested
  default selection are rejected before writes. No member insertion, nested
  flattening, arbitrary rule rewriting, or dedicated-group normalization occurs.
- DIRECT/REJECT/nested group choices never become concrete startup selections.
  They retain the previous `.selected` file; the card continues to identify that
  actual startup/DNS node, not the business default. Existing routing validation
  still rejects an unsupported `MATCH,REJECT` outcome.
- With no default group, startup selection retains legacy save behavior. No rules
  are created. Explicit `MATCH,DIRECT` and `MATCH,<concrete node>` remain intact.

## Read contract and import/profile/subscription coherence

`GET /nodes` preserves its config-byte `etag` and separates these facts:

- `nodes[].selected`: the actual validated `.selected` startup node (and the
  source of the TUN DNS `anytls-out` detour), never replaced by a routing choice.
  Missing/stale/unreadable selection marks no startup card.
- `nodes[].defaultSelected`: only the direct concrete member currently chosen by
  the final MATCH select group. Nested groups, DIRECT and explicit MATCH node
  rules do not mark a direct group choice.
- `selection_linked`: true only when that direct concrete default choice equals
  the actual startup choice. False alone does not imply a card repair is possible.
- `nodes[].selectionNeedsSync`: true only during a startup/default mismatch for
  selectable concrete members that the existing group editor can update. Choosing
  any such member explicitly synchronizes both values, including clicking either
  the existing startup A or the default B once. A default-group DIRECT choice can
  be explicitly replaced by a concrete member. Nested default choices, unsupported
  edits, nonmembers and explicit MATCH node/DIRECT rules never get repair flags.

The current startup card is disabled only when no synchronization is needed.
Mismatch labels must distinguish "startup, default group needs synchronization"
from "default outlet, set as startup"; B must not be labeled the current startup
while `.selected=A`. With explicit MATCH node/DIRECT the card changes startup/DNS
only, never that rule, and no default-rule repair is claimed.

Profile switching and import commit retain their existing byte-preserving
transactions. Subscription refresh retains its existing typed-node-identity and
explicit-group-choice checks. They do **not** silently rewrite independent saved
choices to match `.selected`. The read projection therefore displays both startup
and direct-default truth immediately, even for older mismatching snapshots.
The next explicit card/default-group selection establishes both stored values.
Subscription retention is covered at its real preparation helpers; this change
has no new network-fetch or production subscription-worker test.

Regression tests compile the real TUN runtime from retained A/default B and
assert DNS `anytls-out` uses A while the business route final uses B. After one
explicit selection request they compile again and assert both use the chosen
node. This verifies compiler output, not a live DNS request or native lifecycle.

## Transaction/security boundary

The authenticated parent router continues to own `actionMu`, Origin/CSRF/session
validation, and startup receipt creation. Both selection handlers reuse the
existing profile backup/CAS/readback/rollback helper, with captured config,
optional selection, and subscription file identities. A supplied If-Match must
match captured config bytes; omission remains compatible with legacy clients.
The WebUI sends the nodes/groups snapshot ETag. No failed validation, CAS,
publication, or readback reaches `finishConfigSave` or service dispatch. Successful
saves use that existing synchronous finish path once; an unchanged save dispatches
nothing. Readback/rollback failure returns the existing explicit PROFILE_* error
codes, including STATE_UNCERTAIN when restoration cannot be verified.

As with the existing profile transaction, this is optimistic multi-file
transactionality, not power-loss/crash atomicity or an OS-wide lock. Hostile
same-UID ancestor replacement or writes between the final check and rename are
not newly solved. Final-component symlinks are refused. A rollback publishes new
inodes and restores bytes/presence, not old inode identities. Legacy clients that
omit If-Match lack client-snapshot fencing but still receive server-side CAS.

CLI `select` / `select-group` still use their existing standalone persistence
paths; this change is the WebUI linkage, not a new CLI multi-file transaction.
No helper/authentication/startup receipt protocol or native lifecycle is changed.
