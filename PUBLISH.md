# Publishing to crates.io

Publishing uses crates.io [trusted publishing](https://crates.io/docs/trusted-publishing):
the `Publish to crates.io` workflow (`.github/workflows/publish.yml`) exchanges a GitHub
OIDC token for a short-lived crates.io token, so no long-lived registry secret is stored
in the repository.

## One-time setup

Configure the trusted publisher for each of `boring-sys`, `boring`, `tokio-boring`, and
`hyper-boring` in its crates.io settings with:

- repository: `cloudflare/boring`
- workflow: `publish.yml`
- environment: `crates-io`

Also create the `crates-io` environment in the GitHub repository settings and restrict it to
the `master` branch. GitHub creates a missing environment *without* protection rules, so
declaring `environment: crates-io` in the workflow is not enough on its own: without a
deployment branch rule, the publish job can run from any branch that edits the workflow.
Add required reviewers (with "prevent self-review") if releases should be approved manually.

crates.io does not pin the branch: it verifies the repository, the workflow filename, and
the environment. The deployment branch rule above is what binds publishing to `master`.

## Releasing a version

1. Bump `[workspace.package].version` **and** the `boring-sys`/`boring`/`tokio-boring`
   entries in `[workspace.dependencies]` in the root `Cargo.toml`, and add the corresponding
   `RELEASE_NOTES` entry. All four published crates inherit the workspace version, and CI
   rejects a release commit whose dependency requirements disagree with it.
2. Merge the release commit to `master` and wait for CI to pass. The workflow publishes the
   tip of `master`, so the bump has to be merged before the tag exists.
3. Tag the current tip of `master` and push the tag:
   `git tag v<version> && git push origin v<version>`.
4. Run the `Publish to crates.io` workflow from the `master` branch with `expected_version`
   set to `<version>`.

The workflow fails unless it is run from `master`, the workspace version matches the input,
and the `v<version>` tag exists and points at the commit being published.

## What the publish job does

Crates are published in dependency order: `boring-sys`, `boring`, `tokio-boring`, then
`hyper-boring`, and cargo waits for the version to reach the index before the next crate is
published. `cargo publish` runs with `--no-verify`, so no build script or proc macro runs
while the registry token is in the environment.

A partially completed release can be rerun with the same inputs: cargo's duplicate-upload
error is treated as done and the run continues with the next crate. The contents and yank
state of an already-published version are not re-checked.

Pushing a tag alone does not publish a release.
