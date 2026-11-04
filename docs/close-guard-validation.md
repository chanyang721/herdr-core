# Close guard candidate validation

Not installed or released. Based on `6809ff5` (v0.1.18 plus the existing
`message_sent` change). Existing message delivery behavior is preserved.

Windows GNU debug build, Rust 1.99.1, Zig 0.16.0, pinned ConPTY package
1.24.260710001. Generated CLI reference and pretty-printed OpenRPC schema updated.

## Checks

- `cargo fmt --all --check`: passed.
- `cargo clippy -p herdr-core --all-targets -- -D warnings`: passed.
- Unit tests: 126 passed, including exact closure, kept subtrees, base36
  addresses, input/new-child races, helper bounds/deadlines, actual Exit evidence,
  durable lost-ACK recovery, signal-free reconciliation, no-signal cancellation,
  input epochs, journal write failure and unverified orphan retention.
  A follow-up regression races new-terminal admission against shutdown 64 times:
  stop may win and reject admission, or admission may win and leave a denied
  stop's `stopping` flag false. The production fix already shares one state lock.
  Review follow-ups cover exact durable no-signal settlement after READY failure,
  cancellation ACK loss and restart; definite audit denial releases only its
  fence; unrelated kept recovery reaches a real production SPAWN frame while an
  uncertain target stays held. Unobserved post-signal exits never become receipts.
- All-target test run: CLI docs 2, CLI examples 2, platform API 1, Windows 32
  passed. Two independently reproduced baseline failures were filtered below.
- New Windows production-pipe tests use real disposable ConPTY shells: denial
  preserves the live shell; CLI kill cannot bypass the guard; lost ACK preserves
  rm evidence; reconciliation returns the original exact receipt without a kill.
- Actual external harness CLI `5b041d4` with isolated local data and core identity
  (earlier checks also used `4ceaa56` and `826f30c`):
  mismatched machine ID denied while the shell stayed live; exact no-signal
  certificate returned; matching actual core ID allowed a fresh operation;
  closed ACK and exact receipt preceded removal. No paid agent was used.
  A newly launched interactive `cmd /d /q` shell then received only bare `exit`, produced an
  actual native Exit witness with positive shell-only history, and passed a new
  no-signal audit with no pre-scan SID binding. Exact receipt preceded removal.
  Profile/AutoRun-disabled flags are mandatory for positive history; missing
  `/d` or `-NoProfile` are negative regressions. Bash and other shells remain
  unknown even with startup-disable flags; effective startup environment is
  not proven or changed. Bash flag order and login/interactive variants are
  negative fixtures, with no actual profile or agent execution required.
  Opaque `cmd /d /c` history remained false: the helper denied its audit, core
  persisted cancellation and returned an exact no-signal proof without cleanup.

## Baseline comparison

The same isolated Windows test executable was run against the candidate and a
task-local copy of the installed `6809ff5` executable. Both failed identically:

| Test | Observed failure on both |
| --- | --- |
| `attach_types_non_ascii_text_unchanged` | Character code 101 instead of 233 |
| `interrupt_is_ctrl_c_the_program_takes` | Timeout waiting for English `Reply from` |

The release-swap test initially failed with Windows disk-full error 112 during
parallel executable copies. Its individual serial rerun and the final serial
Windows run both passed. No user data or shared build cache was deleted.

## Limits and application conditions

Independent review is required before application. No installation, existing
core/app restart, real work-session termination, upstream publication or release
was performed. Linux/macOS native runtime integration was not executed here.
The package is the tested Windows debug candidate, not an optimized release.

Configure only the generic argv array. Bind the actual core identity to the
external authorizer's independent endpoint and records. Deploy matching helper
and app contracts together. Older running holders do not acquire new sweep
behavior merely because core is replaced; holder rollout requires separate
coordination. Remote close remains denied. Natural-exit cleanup needs an exact
pre-exit SID/generation binding and current external completion evidence;
unbound historical agents and unknown/partial outcomes remain held. A newly
observed ordinary shell can instead use positive shell-only provenance; absence
of an agent label or SID alone never qualifies. Uncertain operations now fence
only overlapping subtrees, including kept recovery, and expose `exit_unobserved`
through read-only snapshots. No manual evidence override was added.

The local candidate archive preserves the candidate/baseline comparison logs,
the successful serial release-swap log, full fixed-suite results and actual
helper smoke evidence. Earlier evidence is retained separately as well.
