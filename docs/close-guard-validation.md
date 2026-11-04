# Close guard candidate validation

Not installed or released. Based on `6809ff5` (v0.1.18 plus the existing
`message_sent` change). Existing message delivery behavior is preserved.

Windows GNU debug build, Rust 1.99.1, Zig 0.16.0, pinned ConPTY package
1.24.260710001. Generated CLI reference and pretty-printed OpenRPC schema updated.

## Checks

- `cargo fmt --all --check`: passed.
- `cargo clippy -p herdr-core --all-targets -- -D warnings`: passed.
- Unit tests: 118 passed, including exact closure, kept subtrees, base36
  addresses, input/new-child races, helper bounds/deadlines, actual Exit evidence,
  durable lost-ACK recovery, signal-free reconciliation, no-signal cancellation,
  input epochs, journal write failure and unverified orphan retention.
- All-target test run: CLI docs 2, CLI examples 2, platform API 1, Windows 31
  passed. Two independently reproduced baseline failures were filtered below.
- New Windows production-pipe tests use real disposable ConPTY shells: denial
  preserves the live shell; CLI kill cannot bypass the guard; lost ACK preserves
  rm evidence; reconciliation returns the original exact receipt without a kill.
- Actual external harness CLI `826f30c` with isolated local data and core identity:
  mismatched machine ID denied while the shell stayed live; exact no-signal
  certificate returned; matching actual core ID allowed a fresh operation;
  closed ACK and exact receipt preceded removal. No paid agent was used.

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
unbound historical sessions and unknown/partial outcomes remain held.
