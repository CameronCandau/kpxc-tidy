# AGENTS.md

## Project Overview

`kpxc-tidy` is an unofficial Rust/Ratatui terminal UI for auditing and carefully cleaning KeePassXC databases through `keepassxc-cli`.

It provides:

- A single-session password prompt
- Menu-driven audit and cleanup workflows
- Preview-first operations with explicit confirmation before changes
- Read-only mode and Markdown report export
- Safe defaults, preferring archive over delete where practical

The tool is designed for manual, controlled maintenance, not unattended automation.

## Core Design Principles

1. Safety first
   - All destructive actions must require explicit confirmation.
   - Prefer archive over delete.
   - Never silently modify data.

2. Report -> Confirm -> Apply
   - Detection logic should be side-effect free.
   - The TUI should show candidates before any write.
   - Write operations must require confirmation.
   - Reload the database after applying changes.

3. Stateless CLI, stateful app
   - `keepassxc-cli` is stateless.
   - The app maintains session state: password, cached DB model, selected screen/finding.
   - Always reload the database after writes.

4. No direct KDBX manipulation
   - Only interact via `keepassxc-cli`.
   - Never parse or write `.kdbx` directly.

## Current Architecture

- TUI layer: Ratatui + Crossterm in `src/main.rs`
- State layer: `App`, `AppConfig`, selected `Screen`, focus state, pending action, progress overlay
- Model layer: XML parsed from `keepassxc-cli export` into `Group` and `Entry`
- Command layer: all vault writes go through `run_keepassxc()` and wrappers such as `cmd_rm`, `cmd_mv`, `cmd_rmdir`, and `cmd_edit_title`

## Security Considerations

- Password is stored in memory only for the duration of the process.
- Password is passed to `keepassxc-cli` via stdin.
- No password should be written to disk, stored in logs, or exposed via command-line arguments.
- Rust does not guarantee secure memory erasure.
- Passkey directory fetches must not send vault domains to a remote API. The current fetch path downloads a fixed public JSON file and matches locally.

## Development Guidelines

When adding a cleanup feature:

1. Add a pure detection function returning candidates.
2. Add report/detail rendering for the candidates.
3. Add a pending action only if the operation writes to the vault.
4. Require confirmation before applying the pending action.
5. Apply through `keepassxc-cli` wrappers only.
6. Reload the database after writes.
7. Add focused tests using synthetic XML fixtures.

When modifying code:

- Do not change command semantics silently.
- Preserve confirmation steps.
- Keep detection logic separate from UI and CLI execution.
- Do not assume unique entry titles or paths.
- Handle duplicates, missing fields, and malformed timestamps.
- Keep reports free of password values.

## Current Features

- Empty groups cleanup
- Duplicate detection by title and URL+username
- Stale entry reports and archive/delete actions
- Recycle-bin reports and purge actions
- Title normalization candidates
- Missing URL report
- Passkey metadata and opportunity report
- SSH-looking entry inventory
- Read-only mode
- Markdown report export

## Known Limitations

- Entry path ambiguity can still matter when KeePassXC contains duplicate names in one group.
- Duplicate resolution is not yet fully per-cluster/per-entry interactive.
- No undo system beyond KeePassXC history and user backups.
- No key-file or YubiKey support yet.
- Automated tests use synthetic XML, not a generated KDBX fixture yet.

## Publishing Guidance

Safe to publish:

- Source code
- Generic synthetic test data
- Documentation that does not include personal vault details

Do not publish:

- Real `.kdbx` files
- Real key files
- Real XML exports
- Reports containing personal entry names, URLs, usernames, or folder structures
- Scripts containing actual local paths

## Quick Mental Model

Think of this tool as a cautious terminal front-end for KeePassXC vault hygiene.

Not:

- a password manager
- a sync tool
- a merge tool
- an unattended cleaner
- an official KeePassXC project
