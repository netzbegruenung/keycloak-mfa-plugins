# Commit messages

Use Conventional Commits: `type(scope): description`. Scope is optional.

- **type**: any standard Conventional Commits type, chosen normally based on the nature of the change.
- **scope**: the module a change is confined to, using these short names:

  | Module dir | Scope |
  |---|---|
  | `app-authenticator` | `app` |
  | `email-authenticator` | `email` |
  | `enforce-mfa` | `enforce-mfa` |
  | `sms-authenticator` | `sms` |
  | `trusted-device-authenticator` | `device` |
  | `mfa-dev-runner` | `dev-runner` |

  Omit the scope for changes spanning multiple modules or the whole repo, e.g. `chore: update Keycloak version to 26.7.0`.

# Committing and creating PRs

Sign commits with the devcontainer's mounted key, inline: `git -c user.signingkey=~/.ssh/id_claude_signing commit -S -m "..."`. Use `gh` (pre-authenticated via `GH_TOKEN`) to push and open PRs. Never persist these as config — no edits to `.git/config` or `~/.gitconfig`, `-c`/env flags only.

The SSH key is for signing only; it has no push access. Since `origin` is an SSH URL, push over HTTPS with gh's credentials: `git -c credential.helper='!gh auth git-credential' push https://github.com/netzbegruenung/keycloak-mfa-plugins.git <branch>`.
