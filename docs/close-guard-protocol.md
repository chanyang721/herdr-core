# Transactional terminal close guard v1 (local candidate; not deployed)

This is a local, opt-in external authorization boundary. No policy records,
workspace rules, credentials or application-specific decision logic belong in core.
The external authorizer owns policy; core owns exact terminal identity, complete
target expansion, input generations, signal delivery and the transaction lifetime.

## App boundary

RPC: `terminal.kill_batch` takes `roots: string[]`,
`expected: { address: string, pid: number, created_ms: number }[]`, and optional
`context` JSON passed unchanged to the authorizer and optional caller-known
`operation_id` (ASCII letters, digits, underscore and hyphen, at most 80 bytes).
The app persists that ID with its immutable plan. This endpoint requires a guard
even when legacy single-terminal kill is enabled. Addresses use the existing core
parser, including normal addresses such as `t1s` and `t21`.
Only canonical local addresses are supported initially. Empty, duplicate,
unknown, remote, missing-child and identity-mismatched requests are denied as a
whole. The expected set must equal the complete live descendant closure of the
roots, not just the subset with `die_with_parent`. A kept child carrying a
`herdr.space` label and its subtree are spared unless explicitly rooted. This
does not broaden a pane close into deleting another kept pane.

On success, return `{ ok: true, operation_id, terminated: [...] }` containing exactly that
identity set. Failure never permits a single-terminal fallback. App state changes
only after an exact successful response. Input generation is captured by core;
the app does not need a new list/get field.

The existing single-terminal kill, automatic parent cleanup and server stop must
pass the same core boundary. Remote forwarding must not bypass it. Denial must
precede `killing`, stopping, registry or signal changes. Server stop must not
continue to holder goodbye after authorization failure.

## External authorizer boundary

Configuration: `close_guard = ["executable", "argument"]`.
It is fixed at core startup. The actual permanent `core.info.id` is supplied as
`core_id` and as every target's `machine_id`; configuration cannot override it.
The authorizer must bind this ID to its independently queried endpoint and records.
A helper receives the
core's explicit `HC_SOCKET` and session, with caller/scope HC variables removed.
UTF-8 Python stdio is selected for interoperability without making policy part
of core.
No shell interpolation. Each operation uses a fresh subprocess and pipes.
Configured-but-unavailable, malformed, unsupported, timed-out and disconnected
authorizers fail closed. There is no reusable standalone allow token.

1. Core writes a bounded JSON line with `version: 1`, a fresh `operation_id`,
   roots, expected identities and the complete target snapshot. The snapshot
   includes terminal identity, program start, parent, reported state/turn and
   core-observed input generation. Policy-specific fields stay external.
2. The authorizer acquires its dispatch lease, validates every target including
   child and session policy evidence, and replies with
   `{version:1,state:"ready",allow:true,operation_id,token,targets}`.
   It keeps the lease while waiting for the outcome.
3. Core revalidates the entire closure and generations immediately before the
   first destructive signal, under the state lock. Changed identity, new child,
   new/queued input, pending spawn or unsupported target cancels the whole batch.
   Preparing does not fence input: report requests may arrive then, invalidating
   the captured input generation. After READY, targets are fenced before durable
   signal intent. A startup epoch prevents input generations being reused after
   restart. Focus, label and document changes also invalidate native preflight.
4. Core waits for observed termination of all targets. It sends an operation-bound
   `{state:"committed"|"cancelled",operation_id,token}` outcome; timeout or
   partial termination is not success. Cancellation is sent only before any signal.
   After a signal, failure leaves the operation unresolved through EOF instead.
   Committed means every target has actual Exit(code/signal) evidence, not merely
   holder loss, a sent signal or a missing record.
5. The authorizer acknowledges that outcome while still holding the lease and
   then releases it. EOF or cancellation releases the lease without granting a
   future operation. Only `{version:1,state:"closed",allow:false,operation_id}`
   plus exit 0 is successful ACK. `denied`, `unclear`, `cancelled`, malformed
   output, EOF, timeout and nonzero exit never return success.

Lines are limited to 256 KiB. READY has a 120-second deadline; the helper's native
outcome deadline is 120 seconds; core's final ACK and exit waits are bounded to
30 seconds each. Each operation uses a fresh process, unique operation ID and
operation-bound token; callers cannot submit a previously obtained allow.

## Conservative limitations

Remote close is denied, including forwarded kills and remote orphan cleanup.
A guarded core with live terminals refuses `server.stop`; close authorized
batches first. This prevents holder goodbye from bypassing policy.

Closing targets are retained through ACK despite `--rm` and prune. Spawn is
temporarily fenced globally during committed closure. Unknown outcomes after
commitment retain a durable operation, fence and terminal evidence for explicit
reconciliation; there is no automatic retry or fallback. Naturally finished
records without a verified native close receipt are retained rather than removed.
Restart restores pending fences and does not fabricate a close receipt.

## Recovery without signals

`terminal.close_reconcile {operation_id,roots,expected,context?}` requires the
original roots and complete identity set, with no duplicates. When every original
target has matching persisted native Exit evidence and is no longer live, core
runs a fresh authorizer using the original snapshot and `context.mode = "reconcile"`.
The authorizer must check its original operation journal and current audit evidence.
Only its closed ACK plus exit 0 clears the fence and returns
`{ok:true,operation_id,terminated:exact_original_expected}`. This method never
sends a signal. Partial, live, changed or unknown outcomes remain held.

A proven pre-signal cancellation instead returns
`{ok:false,operation_id,state:"cancelled",no_signal:true,expected:exact_original_expected}`.
It has no `terminated` field and permits only retry with the model preserved.
Native preflight refusals and verified helper denied/exit1 or cancelled/exit1
are recorded separately from unknown outcomes. Existing uncertain operations
cannot be overwritten with a cancellation. `close_retry_safe` errors identify
definite refusal; clients can obtain the exact certificate through reconciliation.

Read-only `terminal.close_snapshot {roots}` (CLI `close-snapshot <terminal>`)
returns `core_id`, `roots`, `expected`, `targets` with `input_generation`,
`program_started_ms`, `turn`, `status`, `native_state` and `observed_exit`, plus
matching operation metadata. It grants no close permission.

An unknown operation ID on explicit reconciliation can create an audit-only
operation only from a complete all-ended closure with durable actual Exit
witnesses. The native operation records `audit_only:true,signalled:false`; the
helper receives `action:"audit",context.mode:"reconcile"` and authoritative
`targets[].observed_exit:true`. The external authorizer must independently match
its pre-exit provider SID/input-generation binding and current report, review,
acceptance and learning evidence. Missing bindings or unknown records are denied
and retained. No automatic cleanup scheduler is added.

Guarded orphan adoption, late spawn cleanup and scope sweeps retain unverifiable
processes instead of sending an unguarded kill. A core with an unverified orphan
refuses stop. Holders started with this configuration suppress automatic scope
sweeps. Enabling this feature requires holders built with this support; older
already-running holders retain their previous behavior and are not upgraded by
this patch. OS termination and programs exiting themselves remain external
events, never represented as an authorized close.

## Verification scope

Tests use disposable programs, an isolated HC_SESSION and temporary XDG paths.
They must cover direct CLI/API kill, closure mismatch, PID/start changes, input
changes, new children, unsupported remote targets, helper failure/EOF/timeout,
READY replay, completion/cancellation ACK and lease lifetime. No installed core,
real agent session or upstream publication is part of this work.
