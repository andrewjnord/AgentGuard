# Building, signing and releasing

## Pipeline

`.github/workflows/build.yml` runs on a Windows runner for every push to `main`, every pull request and every `v*` tag:

1. Type-checks the dashboard, builds the solution and runs all tests (results uploaded as `test-results`).
2. Publishes every binary self-contained for win-x64 into one folder (`build/publish.ps1`); no .NET install is needed on target machines.
3. Signs AgentGuard's own executables and DLLs, builds the MSI with WiX v5, and signs the MSI (skipped when no certificate is configured).
4. Installs the MSI on the runner, checks the service, API, dashboard, admin CLI, Claude Code hook and tray, then uninstalls it and checks the cleanup (`build/smoke-test.ps1`, logs uploaded as `smoke-test-logs`). The runner is not a real desktop, so tray checks there are warnings; confirm the tray on a real machine.
5. Uploads the MSI (`AgentGuard-<version>`). A `v1.2.3` tag also creates a GitHub release with the MSI attached.

Versions: tags give the release version (`v1.2.3` → `1.2.3`); other builds are `0.1.<run number>`.

## Code signing

Add two repository secrets (Settings → Secrets and variables → Actions):

| Secret | Value |
| --- | --- |
| `SIGNING_CERT_PFX` | Base64 of the code-signing certificate `.pfx` (`[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`) |
| `SIGNING_CERT_PASSWORD` | The `.pfx` password |

Without them the pipeline still builds an unsigned MSI. Signing uses SHA-256 with an RFC 3161 timestamp (DigiCert by default) so signatures stay valid after the certificate expires. If the certificate lives in an HSM or Azure Trusted Signing instead of a `.pfx`, replace `build/sign.ps1`; the pipeline only calls it with a list of files.

## Installer behaviour

- Installs to `C:\Program Files\AgentGuard`, registers the `AgentGuard` service (LocalSystem, automatic start, restart on failure), starts the tray for every user at sign-in, and adds a Start menu shortcut that opens the dashboard.
- Registers the Claude Code PreToolUse hook machine-wide in `C:\Program Files\ClaudeCode\managed-settings.d\agentguard.json`. Skip with `msiexec /i AgentGuard.msi INSTALLCLAUDEHOOK=0`.
- Upgrades in place (major upgrade); downgrades are refused.
- Uninstall first runs `agentguard cleanup-integrations` so MCP clients routed through the proxy get their original configuration back and the Claude Code hook is removed, then removes the program. The data folder `C:\ProgramData\AgentGuard` (audit log, policy history) is kept as evidence; delete it by hand if it is not needed.

Silent install for fleet deployment: `msiexec /i AgentGuard-<version>-x64.msi /qn /l*v install.log`.

## Building locally (Windows)

```
./build/publish.ps1 -Version 0.1.0 -Output artifacts/app
dotnet build installer/AgentGuard.Installer.wixproj -c Release -p:ProductVersion=0.1.0 -o artifacts/msi
```
