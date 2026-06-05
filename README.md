# vigil

**Fast, opinionated dependency vulnerability scanner for JavaScript & TypeScript projects — powered by [OSV.dev](https://osv.dev).**

`vigil` reads your lockfile, figures out the *exact* versions you have installed, and checks every one of them against the OSV.dev advisory database (which aggregates the GitHub Advisory Database, the npm advisory feed, and CVEs). It reports **known** vulnerabilities — with a real severity and the version that fixes them — not heuristic guesses.

```
! 6 known vulnerabilities across 1 package(s) (pnpm-lock.yaml):
  0 critical · 3 high · 3 other

  [high] lodash@4.17.15 (direct)
      Command Injection in lodash
      GHSA-35jh-r3h4-6jhm (CVE-2021-23337)
      fix: upgrade to 4.17.21
      https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
```

## Why vigil

- **Lockfile-native.** Reads `pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, and `bun.lock` directly — exact installed versions, not `package.json` ranges.
- **Tells you *why* a vuln is there.** For a transitive dependency, vigil shows the chain that pulls it in — `via vite › esbuild` — so you know which parent to upgrade instead of staring at a package you never installed.
- **Livable in CI.** A `.vigilignore` lets you mute a specific advisory with a reason and an optional expiry, so one unfixable transitive vuln doesn't block every build. Expired or dead ignores are flagged so they don't rot.
- **No API key, no account.** Queries the public OSV.dev API. Your package names + versions are the only thing sent; never your code.
- **Fast & cached.** Parallel queries with an on-disk cache under `.vigil/osv`, so re-runs (and CI) are near-instant.
- **CI-ready.** `--fail-on <severity>` gates your pipeline; `--format sarif` drops straight into the GitHub Security tab.
- **Honest about blind spots.** No lockfile? It falls back to `package.json` ranges and *tells you* the result isn't exact. Network hiccup? It reports how many packages went unchecked instead of pretending the tree is clean.

## Install

```bash
# From source (requires a recent Rust toolchain)
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

```
package.json + lockfile  ──▶  resolve exact installed versions
        │                     (pnpm-lock.yaml > package-lock.json > yarn.lock > bun.lock;
        │                      falls back to package.json ranges with a blind-spot flag)
        ▼
query OSV.dev  ──────────▶  POST /v1/query per package — OSV does the version-range
        │                    matching server-side; results cached under .vigil/osv
        ▼
findings  ───────────────▶  severity (GHSA label → CVSS → unknown), CVE/GHSA ids,
                             lowest published fix above the installed version
        │
        ▼
human / JSON / SARIF
```

## Status & roadmap

Early but working — npm/pnpm/yarn/bun lockfiles, live OSV matching, human/JSON/SARIF output, CI gating. Validated against real-world projects (a 1500-package Bun monorepo surfaces correctly with direct/transitive attribution and per-version dedup).

Shipped in v0.2: transitive "why is this here" paths and `.vigilignore` suppressions.

Planned:

- `vigil fix` — auto-upgrade the lockfile to the fixed versions
- License compliance + malicious-package (OSV `MAL-`) checks
- GitHub Action + scheduled re-scans (catch newly-published CVEs without a code change)
- `--offline --db <path>` mode for air-gapped CI (downloadable OSV snapshot)
- More ecosystems (OSV supports PyPI, crates.io, Go, …)

## License

MIT © 2026
