# Contributing

Thanks for improving the Lenso Passkey Auth Plugin. This repository contains the
portable Passkey Capability and its removable PostgreSQL implementation; keep
browser routes, cookies, canonical identities, App sessions, recovery, and RBAC
in their owning Adapter or product repository.

## Choose a contribution path

- **Editor:** make a focused change in a fresh clone, run the narrow checks
  below, and attach the immutable base and candidate SHAs to the Issue.
- **Delta:** use a task-owned isolated clone. Delta Land is the managed delivery
  path described by `.agents/skills/land/SKILL.md`; it is not a general shell
  command or a permission to alter another checkout.
- **AI or other agents:** preserve the same ownership boundary and review
  evidence. An agent must not publish, deploy, rotate credentials, or touch a
  different clone or repository.

Forks and Issue handoffs are welcome. An Issue handoff must name the fork,
branch, base SHA, candidate SHA, checks run and their limitations. SHAs are
immutable: do not ask a maintainer to review an unpinned branch tip.

## Focused checks

For docs or workflow-only changes, run the relevant Markdown/YAML parsing and
diff checks, for example:

```sh
ruby -e 'require "yaml"; ARGV.each { |p| YAML.load_file(p, aliases: true) }' .github/workflows/*.yml
 git diff --check
```

For Rust changes, use the repository toolchain and the focused checks in the
README and release process. PostgreSQL acceptance requires
`LENSO_POSTGRES_TEST_URL`; without it, say explicitly that the database proof
was not run. Local checks do not replace candidate CI. Do not claim native or
PostgreSQL coverage when it was not executed.

Keep a durable patch for review or transfer when needed:

```sh
git format-patch --binary --stdout origin/main..HEAD > passkey-change.patch
```

A maintainer imports the patch or candidate into a clean checkout, reviews the
full diff and the ownership boundary, and decides whether to land it. Treat
workflow files, scripts, and release configuration as untrusted code: inspect
before running and never add secrets or credentials to them.

## Candidate CI and landing

The required `check` job runs first on a pushed `delta/verify/**` candidate (or
via the workflow dispatch control). A candidate must be based on the current
`origin/main`, and the exact candidate SHA, workflow run, ref, and required jobs
must be recorded before landing. Candidate CI is the authoritative proof; local
results are supporting evidence only.

After candidate success, the maintainer may fast-forward `main` to that same
SHA and verify that the remote still reaches it. Do not force-push, rewrite a
verified candidate, create a PR, publish packages, or deploy. Release-plz is a
manual immutable-SHA dry-run only; publication remains a separate, explicitly
authorized future boundary.

**Delta Land** means this repository's managed candidate/fast-forward procedure.
`/land` is a separate Delta operation and is not universal shell syntax or a
permission model. Contributors using another agent or plain Git follow this
document and the maintainer's import/review process instead.
