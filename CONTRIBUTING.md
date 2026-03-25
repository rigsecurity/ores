# Contributing to ORES

Thank you for your interest in contributing to ORES (Open Risk Evaluation & Scoring). This document describes the process for contributing code, documentation, and feedback. We welcome contributions of all kinds from the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Developer Certificate of Origin](#developer-certificate-of-origin)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Running Tests](#running-tests)
- [Linting](#linting)
- [Pull Request Process](#pull-request-process)
- [Commit Message Format](#commit-message-format)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

This project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its standards. Violations may be reported to `conduct@rig.security`.

## Developer Certificate of Origin

ORES requires that all contributors sign off on their commits using the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This is a lightweight mechanism (not a CLA) to certify that you wrote or otherwise have the right to submit the code you are contributing.

Add a `Signed-off-by` trailer to every commit:

```
git commit -s -m "feat(signals): add EPSS signal parser"
```

This produces a commit with the following trailer:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The sign-off must use your real name and a reachable email address. Pseudonyms and anonymous contributions are not accepted.

If you have already made commits without a sign-off, you can amend them:

```bash
# Amend the most recent commit
git commit --amend --signoff

# Amend multiple commits (replace N with the count)
git rebase --signoff HEAD~N
```

## Getting Started

### Prerequisites

| Tool | Minimum Version | Install |
|------|----------------|---------|
| Go | 1.25 | https://go.dev/dl/ |
| Task | 3.x | https://taskfile.dev/installation/ |
| golangci-lint | 2.x | https://golangci-lint.run/welcome/install/ |
| buf | latest | https://buf.build/docs/installation |
| git | 2.x | https://git-scm.com/ |

### Fork and clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/<your-username>/ores.git
cd ores
git remote add upstream https://github.com/rigsecurity/ores.git
```

### Install dependencies

```bash
go mod download
```

## Development Workflow

1. Sync your fork with upstream before starting work:

   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. Create a feature branch. Branch names should be descriptive and use lowercase kebab-case:

   ```bash
   git checkout -b feat/epss-signal-parser
   ```

3. Make your changes. Keep commits small and focused - one logical change per commit.

4. Run the full test and lint suite before pushing:

   ```bash
   task test
   task lint
   ```

5. Push your branch and open a pull request against `main`.

## Running Tests

Run the full test suite with the race detector enabled:

```bash
task test
```

This outputs a `coverage.txt` file. To view coverage in your browser:

```bash
go tool cover -html=coverage.txt
```

For a quick iteration loop without the race detector:

```bash
task test:short
```

All new code must include tests. We target a minimum of 80% line coverage for new packages. Table-driven tests using [testify](https://github.com/stretchr/testify) are the preferred style.

### Test conventions

- Use `assert` for non-fatal checks and `require` for fatal checks (where the test cannot continue on failure).
- Name test functions `Test<Function>_<scenario>` when a function has multiple test cases.
- Keep test helpers in `internal/testutil` so they can be shared across packages.

## Linting

```bash
task lint
```

ORES uses [golangci-lint v2](https://golangci-lint.run/) with a strict ruleset defined in `.golangci.yml`. All issues must be resolved before a PR can be merged. The CI pipeline enforces this check automatically.

Key linters in use:

- `staticcheck` and `govet` - correctness
- `errcheck` and `errorlint` - proper error handling
- `gosec` - security anti-patterns
- `sloglint` - consistent structured logging
- `testifylint` - proper use of the testify assertion library
- `unparam`, `unused`, `ineffassign` - dead code elimination

## Pull Request Process

1. **One concern per PR.** A pull request should address exactly one bug, feature, or refactor. Large changes are harder to review and slower to merge.

2. **Fill in the PR template.** Describe what the change does, why it is needed, and how you tested it. Link any related issues with `Closes #<issue>`.

3. **Keep the diff small.** If your feature requires scaffolding changes, consider splitting them into a preparatory PR.

4. **Respond to review feedback promptly.** A PR with no activity for 14 days may be closed.

5. **Do not force-push after review begins.** It makes diff tracking difficult for reviewers. Use additional commits instead, and they will be squashed at merge.

6. **All CI checks must pass** before a PR is eligible for merge.

7. **Two approvals** from maintainers are required to merge to `main`.

## Commit Message Format

ORES uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). Commit messages must follow this format:

```
<type>(<scope>): <subject>

[optional body]

[optional footers]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or correcting tests |
| `chore` | Maintenance tasks (deps, CI, tooling) |
| `perf` | Performance improvement |
| `build` | Build system or external dependency changes |
| `ci` | Changes to CI/CD configuration |

### Scopes

Scopes map to top-level packages or components. Examples: `signals`, `engine`, `model`, `explain`, `cli`, `daemon`, `wasm`, `proto`.

### Examples

```
feat(signals): add EPSS signal parser with decay weighting

fix(engine): prevent nil dereference when signal list is empty

docs(contributing): add DCO sign-off instructions

test(model): add table-driven tests for weighted composite scoring

chore(deps): update buf to v1.34.0
```

### Subject line rules

- Use the imperative mood: "add", "fix", "remove" - not "added", "fixes", "removed"
- Do not capitalize the first letter
- No period at the end
- Maximum 72 characters including type and scope

### Breaking changes

Append `!` after the type/scope and include a `BREAKING CHANGE:` footer:

```
feat(proto)!: rename EvaluateRequest fields to match v1 schema

BREAKING CHANGE: The `cvss_vector` field is now `cvss_string`.
Clients must update their request payloads accordingly.
```

## Reporting Issues

- **Bugs:** Open a GitHub issue using the bug report template. Include the ORES version (`ores --version`), Go version, OS, and a minimal reproduction.
- **Feature requests:** Open a GitHub issue using the feature request template. Describe the use case, not just the solution.
- **Security vulnerabilities:** Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

Thank you for helping make ORES better.
