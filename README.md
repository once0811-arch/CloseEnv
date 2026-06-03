# CloseEnv

CloseEnv is a small secretless repository scanner. It is designed for the
pre-open-source moment: before publishing a repository, run one command and get
a value-free report of files and patterns that still look secret-bearing.

CloseEnv never prints detected secret values. Findings include only the path,
check name, and detector label.

## Why CloseEnv?

Maintainers often need one last check before opening a private repository,
accepting a drive-by PR, or cutting a release from a machine with local dev
state. CloseEnv focuses on that workflow: fast Git-aware scanning, value-free
reports, CI-friendly output, and high-confidence publish blockers.

## Usage

```bash
cargo run -- scan
cargo run -- scan /path/to/repo
cargo run -- scan --json
cargo run -- scan --sarif
cargo run -- scan --staged
cargo run -- scan --no-fail
cargo run -- --version
```

The default exit code is `1` when blocker findings are present. Use
`--no-fail` when you want a report without failing a local script.

Useful CI options:

```bash
closeenv scan --staged
closeenv scan --sarif > closeenv.sarif
closeenv scan --max-files 25000 --max-file-bytes 524288
closeenv scan --limit 20
```

## Checks

- tracked dotenv value files such as `.env` and `.env.local`
- working-tree dotenv value files
- concrete secret-looking values in `.env.example` and `.env.sample`
- high-confidence raw token patterns without printing matched values, including
  OpenAI, GitHub, Slack, npm, Stripe, Google API, AWS access key, JWT,
  bearer token, signed URL, database URL, and private key detectors
- sensitive assignment values with high entropy
- sensitive file names such as SSH private keys, `.npmrc`, `.pypirc`,
  `.aws/credentials`, `.kube/config`, and service account JSON files
- repo-local secret state such as `.envforge/token`, `.envrc`, and `.direnv`
- package scripts that load plaintext dotenv files
- Docker Compose `env_file` usage

## Configuration

Create `closeenv.yml` or `.closeenv.yml` at the repo root:

```yaml
closeenv:
  allow_value_env_paths:
    - .env.test
    - fixtures/**
  ignore_paths:
    - snapshots/**
  ignore_detectors:
    - signed-url
  max_files: 50000
  max_file_bytes: 1048576
```

Allowlist entries support exact paths and `/**` directory prefixes. CloseEnv
ignores allowlist entries that themselves look secret-bearing.

When scanning a Git repository, CloseEnv uses `git ls-files -co --exclude-standard`
by default so ignored dependency and build outputs are skipped quickly. Use
`--include-ignored` for a full filesystem walk.

`--staged` is intended for pre-commit hooks and scans only staged added,
copied, modified, or renamed files.

Example integrations live in `examples/`:

- `examples/github-action.yml` emits SARIF for GitHub code scanning.
- `examples/pre-commit.sh` scans staged files before a commit.

## Maintainer Workflows

```bash
# Before making a repository public
closeenv scan --sarif > closeenv.sarif

# Before committing local changes
closeenv scan --staged

# For large repos
closeenv scan --max-files 25000 --max-file-bytes 524288
```

## Security Model

CloseEnv is a static scanner, not a vault and not a secret rotation system. It
is meant to catch common publish blockers before code is pushed to a public
remote. If it finds a real secret, rotate that secret in the provider after
removing it from the repository history.
