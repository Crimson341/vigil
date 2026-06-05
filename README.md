# vigil

A command-line tool that checks your JavaScript/TypeScript dependencies for known security vulnerabilities.

It reads your lockfile (pnpm, npm, yarn, or bun), looks up every installed package in the [OSV.dev](https://osv.dev) vulnerability database, and tells you which ones have known problems and what version fixes them.

```
! 6 known vulnerabilities across 1 package(s) (pnpm-lock.yaml):
  0 critical · 3 high · 3 other

  [high] lodash@4.17.15 (direct)
      Command Injection in lodash
      GHSA-35jh-r3h4-6jhm (CVE-2021-23337)
      fix: upgrade to 4.17.21
      https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
```

## What it does

- Finds vulnerable packages in your dependency tree
- Shows which version to upgrade to
- For deep dependencies, shows what's pulling them in (e.g. `via vite › esbuild`)
- Lets you ignore issues you've already handled (`.vigilignore`)
- Works in CI — the exit code can fail your build when something's found
- No API key or account needed; only package names and versions are sent, never your code

## Install

```bash
git clone https://github.com/Crimson341/vigil
cd vigil
cargo install --path .
```

## Usage

```bash
vigil                              # scan the current directory
vigil --path ./my-app              # scan a specific project
vigil --prod-only                  # skip dev-only dependencies
vigil --fail-on high               # exit 1 if any high/critical (for CI gates)
vigil --format json                # machine-readable
vigil --format sarif --sarif-file vigil.sarif   # upload to GitHub code scanning
vigil --refresh                    # ignore the cache and re-query
```

### Suppressing findings (`.vigilignore`)

Drop a `.vigilignore` file at your project root to mute advisories you've triaged — gitignore-style, one matcher per line:

```text
# match an OSV id, a CVE id, or a bare package name
GHSA-p6mc-m468-83gw                      # reason after a hash
CVE-2021-23337   until=2026-12-31        # expires; re-surfaces after this date
lodash                                   # mute every advisory for a package
```

Expired suppressions stop muting (the finding returns) and dead ones (matched nothing) are reported as stale, so your ignore list doesn't rot. Use `--no-ignore` to report everything regardless.

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean, or advisory mode (findings reported, no gate) |
| `1`  | `--fail-on <severity>` threshold met |
| `2`  | Setup error (no resolvable deps, bad SARIF path, …) |
| `7`  | Offline with a cold cache — every OSV query failed |

### Environment

- `VIGIL_OSV_API_URL` — override the OSV API base (staging / testing / a mirror).

## How it works

1. Read the lockfile to get the exact version of every installed package.
2. Ask OSV.dev which of those versions have known vulnerabilities.
3. Print the results, with the fix version and (for deep dependencies) what pulls them in.

Results are cached under `.vigil/osv`, so repeat runs are fast. If there's no lockfile, it falls back to the `package.json` version ranges and warns you that the result isn't exact.

## Status

Works today on pnpm, npm, yarn, and bun projects, with human, JSON, and SARIF output. Still early.

Planned:

- `vigil fix` — auto-upgrade the lockfile to the fixed versions
- License compliance + malicious-package (OSV `MAL-`) checks
- GitHub Action + scheduled re-scans (catch newly-published CVEs without a code change)
- `--offline --db <path>` mode for air-gapped CI (downloadable OSV snapshot)
- More ecosystems (OSV supports PyPI, crates.io, Go, …)

## License

MIT © 2026
