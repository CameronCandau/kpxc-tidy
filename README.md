# kpxc-tidy

`kpxc-tidy` is an unofficial terminal UI for auditing and carefully cleaning KeePassXC databases through `keepassxc-cli`.

It is built for manual vault maintenance:

- Load a read-only model from `keepassxc-cli export`
- Report cleanup candidates before changing anything
- Require explicit confirmation before writes
- Prefer archiving over deleting where practical
- Reload the database after every write

It never parses or writes `.kdbx` files directly.

## Status

Early Rust project. It has been useful on real vault-cleanup work, but use `--read-only` first and keep a backup before applying changes.

This project used AI assistance heavily.

## Features

- Empty group cleanup
- Duplicate title and URL+username reports
- Safer duplicate archiving/deletion for older URL+username candidates
- Stale entry reports and archive/delete actions
- Recycle-bin reports, old-entry purge, and empty recycle-bin group purge
- Title normalization candidates
- Missing URL report
- Passkey metadata report and local Passkeys Directory candidate matching
- SSH-looking entry inventory
- Read-only mode
- Markdown report export

## Install

From source:

```sh
cargo install --path .
```

After crates.io publishing:

```sh
cargo install kpxc-tidy
```

`keepassxc-cli` must be installed and available in `PATH`. You can override it with `KEEPASSXC_CLI=/path/to/keepassxc-cli`.

## Run

```sh
kpxc-tidy path/to/database.kdbx
```

Useful options:

```sh
kpxc-tidy path/to/database.kdbx --read-only
kpxc-tidy path/to/database.kdbx --report kpxc-tidy-report.md
kpxc-tidy path/to/database.kdbx --stale-years 3 --recycle-days 30 --archive-group Archive/AutoCleanup
```

Passkey support matching uses local data. On the Passkeys screen, press `f` to download the public Passkeys Directory support list into a local cache. The app fetches only the fixed directory URL and does not send vault domains anywhere.

You can also download a Passkeys Directory JSON file yourself, then pass it in:

```sh
kpxc-tidy path/to/database.kdbx --passkey-directory supported.json
```

## TUI Controls

- `j` / `k` or arrow keys: move through audit categories or findings
- `Tab`: switch focus between audit categories and findings
- `h` / `Left`: focus audit categories
- `l` / `Right`: focus findings
- `Enter`: open details for the selected finding
- `w`: write a Markdown report
- `r`: refresh the database model
- `q`: quit

## Safety Notes

The database password is kept only in process memory and is passed to `keepassxc-cli` through stdin. It is not written to logs or passed as a command-line argument.

Rust improves implementation safety, but it cannot guarantee secure memory erasure or make destructive operations risk-free. Back up important vaults before applying cleanup actions.

`kpxc-tidy` is a wrapper around `keepassxc-cli`, not a replacement for KeePassXC. KeePassXC already has its own password health reports, passkey support, SSH agent integration, and CLI. This tool focuses on terminal-based vault hygiene workflows.

## Publishing Notes

Before publishing a release, run:

```sh
cargo fmt --check
cargo test
cargo clippy -- -D warnings
cargo package --list
cargo package
```

Do not publish real `.kdbx` files, key files, XML exports, reports with personal URLs, or local paths from a real vault.

## License

`kpxc-tidy` is licensed under GPL-3.0-or-later.
