# Contributing

Thanks for helping improve riskAPI. This page covers how to send a change and what CI does with it.

## Sending a change

1. Fork the repository.
2. Create a branch for each change (`git checkout -b fix/short-description`). Do not open pull requests from your fork's `master`: every later push to it ends up in the same pull request.
3. Make the change, with tests where it affects behavior.
4. Open a pull request against `master` and describe what changed and why.

Keep one topic per pull request. Unrelated changes are easier to review and merge separately.

## Local setup

The steps are the same on Linux, macOS and Windows; only the shell differs.

### Prerequisites

| | Linux / macOS | Windows |
|---|---|---|
| Go | Version from the `go` directive in `go.mod` | Same |
| Shell for the scripts | Any terminal with `bash` | Git Bash (installed with [Git for Windows](https://git-scm.com/download/win)), or WSL |
| GitHub CLI | `gh`, signed in with `gh auth login` | Same |
| C compiler (only for `go test -race`) | `gcc` or `clang`, usually already installed | MinGW-w64 `gcc` on `PATH` |

### Geolocation databases

The databases are not stored in git. Download them into `providers/` before running the server or building the image. The script uses `gh` to fetch the last known good set from the upstream `geo-data` release. MaxMind and IPinfo tokens are optional; without them it uses that release as is.

Linux, macOS, WSL, or Git Bash on Windows:

```bash
./scripts/fetch-geo-data.sh
```

PowerShell on Windows:

```powershell
& "C:\Program Files\Git\bin\bash.exe" scripts/fetch-geo-data.sh
```

Do not run plain `bash` from PowerShell or cmd: on Windows that name can resolve to the WSL launcher instead of Git Bash.

### Checks before pushing

These commands work the same in any shell:

```bash
gofmt -l .
go test -race ./...
```

`gofmt -l .` should print nothing. If you have no C compiler, run `go test ./...` instead; CI runs the race detector on every pull request.

### Line endings

Text files use LF, enforced by `.gitattributes`. If you cloned on Windows before that file was added, the scripts may have CRLF endings and fail in Git Bash with `$'\r': command not found`. Re-normalize the working tree once:

```bash
git rm -r --cached -q . && git reset --hard
```

This discards uncommitted changes, so commit or stash first.

## What CI does

| Where it runs | Build, tests, `govulncheck`, image build | Push image, update `geo-data` release, deploy |
|---|---|---|
| Pull request (from a fork or an upstream branch) | Yes | No |
| Manual run on a non-`master` branch | Yes | No |
| `master` (push, daily schedule, manual run), upstream or in your fork | Yes | Yes, using that repository's own secrets |

The workflow does not start on pushes to other branches. To publish and deploy from your fork's `master`, see [Running the full pipeline in your fork](#running-the-full-pipeline-in-your-fork).

Things to know about pull requests from forks:

- **No secrets.** GitHub does not pass repository secrets to pull requests from forks. The image is built under a placeholder name and is never pushed. A pull request cannot be used to test publishing or deployment.
- **Approval may be required.** For first-time contributors, a maintainer has to approve the workflow run before it starts.
- **Docs-only changes skip CI.** Changes limited to `README.md`, `README_cn.md` or `docs/` do not trigger the workflow.

If CI fails on a step that needs credentials you do not have, mention it in the pull request instead of working around it.

## Running the full pipeline in your fork

You do not need any of this to contribute. It is for running your own copy of the service: on your fork's `master`, the workflow pushes the image to your Docker Hub account and redeploys your Koyeb service.

The publishing steps run in order and each one stops the job if it fails:

| Step | What it needs in your fork |
|---|---|
| Fetch geo databases | Nothing. Falls back to the upstream `geo-data` release. |
| Push image to Docker Hub | Secrets `DOCKER_USERNAME` and `DOCKER_PASSWORD` |
| Update `geo-data` release | A release tagged `geo-data` in your fork (forks do not copy releases) |
| Redeploy Koyeb service | Secrets `KOYEB_API_TOKEN` and `KOYEB_SERVICE_ID`, and an existing Koyeb service |

### One-time setup

1. **Enable Actions.** Open the Actions tab of your fork and enable workflows. The daily schedule has to be enabled separately there; leave it off if you only want deployments on push.
2. **Add the Docker Hub secrets** under Settings → Secrets and variables → Actions:
   - `DOCKER_USERNAME`: your Docker Hub username. The image is pushed as `<username>/risk-api`, tagged `latest` and with the run ID.
   - `DOCKER_PASSWORD`: a Docker Hub access token with write permission.
3. **Create the `geo-data` release** in your fork:

   ```bash
   gh release create geo-data --repo <you>/riskAPI --title "geo-data" --notes "Last known good geolocation databases"
   ```

4. **Run the workflow once** (push to `master`, or Actions → docker release → Run workflow). The image is pushed and the release is filled. The last step, the Koyeb redeploy, fails because there is no service yet.
5. **Create the Koyeb service** from `docker.io/<username>/risk-api:latest`, exposing port `8080`. If your Docker Hub repository is private, add a registry secret in Koyeb so it can pull the image.
6. **Add the Koyeb secrets**:
   - `KOYEB_API_TOKEN`: an API token from your Koyeb account.
   - `KOYEB_SERVICE_ID`: the ID of the service created in step 5.
7. **Re-run the workflow.** All steps should now pass, and later pushes to `master` redeploy the service.

### Optional secrets

`MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY` and `IPINFO_TOKEN` let the workflow download fresh MaxMind and IPinfo databases. Without them it uses the copies from the upstream `geo-data` release.

### Things to know

- The redeploy step only triggers a new deployment of an existing service. It does not create the service or change its configuration.
- The job ends when the redeploy request is accepted. It does not wait for the deployment to become healthy, so check the Koyeb dashboard after the first run.
- Environment variables for the service (see the README) are set in Koyeb, not in the workflow.
