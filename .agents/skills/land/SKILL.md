# Land the Passkey Plugin

Use this skill only for this repository after implementation and review.

1. Start from the current `origin/main`; preserve unrelated work and confirm a
   clean task clone.
2. Run focused docs/YAML/diff checks, inspect the complete diff, and absorb
   review fixes before committing with a concise Conventional Commit subject.
3. Push the exact commit once to a unique `delta/verify/lenso-auth-passkey-plugin/<attempt>`
   ref. Accept only the CI workflow run triggered by that ref whose `check` job
   succeeds for that exact SHA. Record the run URL, ref, SHA, and job result.
4. Only after that proof, inspect the live branch protection and apply the
   existing owner-approved pattern: required checks bound to GitHub Actions app
   `15368`, strict mode, admin enforcement, linear history, no force pushes or
   deletions, preserving other policy and leaving required pull-request reviews
   unset/null.
5. Fast-forward `main` to the same verified SHA normally. Read back the remote
   SHA and protection, verify the candidate is reachable, ensure no duplicate
   main CI ran, and delete the temporary candidate ref.

This is Delta Land, not a universal `/land` shell command or permission grant.
Other agents and plain Git users should provide the immutable patch/SHA and let
an authorized maintainer import, review, and land it. Never force-push, publish,
deploy, rotate credentials, or create a pull request as part of this procedure.
