# Post-Creation Verification Checklist

Use this checklist after generating a new module to verify everything is complete.

## Module Structure
- [ ] Module file exists at `pkg/exploits/{service}_{technique}/module.go`
- [ ] Package name matches directory (e.g., `package ecs_passrole`)
- [ ] Module struct embeds `modules.BaseModule`

## PathInfo
- [ ] ID follows `{service}-{number}` convention matching pathfinding.cloud
- [ ] Name matches the permission-based name from YAML (e.g., "iam:PassRole + ecs:...")
- [ ] Category is one of: self-escalation, principal-access, new-passrole, existing-passrole, credential-access
- [ ] Services lists all involved AWS services, lowercase
- [ ] Description is human-readable
- [ ] Permissions.Required lists all required IAM actions
- [ ] Permissions.Additional lists optional/helper permissions
- [ ] Prerequisites.Admin and .Lateral are populated from YAML
- [ ] References includes pathfinding.cloud URL
- [ ] MITRE mapping is populated
- [ ] Author is "Seth Art"
- [ ] Aliases include old-style name (e.g., "exploit/ecs_passrole") and short form (e.g., "ecs-passrole")

## Registration
- [ ] `init()` function calls `modules.Register("{service}-{number}", constructor)`
- [ ] Blank import added to `cmd/pathrunner/main.go`

## Interface Methods
- [ ] `Options()` returns all module options with correct Required/Default values
- [ ] `Execute()` implements the full exploitation flow
- [ ] If payload-based: `PayloadOptions()` and `ListPayloads()` are overridden
- [ ] If payload-based: `PayloadCompatible` interface is implemented (`GetCompatibleTags()`, `GetPayloadContext()`)

## Resource Tracking
- [ ] ALL created AWS resources call `tracker.TrackResource()` with:
  - Correct `Type` (e.g., "ecs:service", "iam:attached-policy")
  - Meaningful `Name`
  - `ARN` if available
  - `Region` set
  - `CleanupMethod` set to the API action
  - `ModuleID` set to the path ID
  - `Metadata` includes info needed for cleanup
- [ ] Cleanup handler exists in `pkg/core/repl/session.go` for each resource type created

## Credential Output
- [ ] If module produces credentials, uses `PATHFINDER_IDENTITY_DATA` structured format
- [ ] Format includes: NAME, TYPE, ACCESS_KEY_ID, SECRET_ACCESS_KEY, SESSION_TOKEN, REGION, EXPIRES_AT

## Payload Reuse
- [ ] Checked existing payloads in `pkg/payloads/{service}/` before creating new ones
- [ ] Only created new payloads when the exploitation pattern requires something not already available
- [ ] If new payload created: registered via `init()`, blank import added if new service directory

## Tags (if new payload created)
- [ ] Service tag exists in `pkg/payloads/tags.go` (add if new service)
- [ ] Language tag matches payload language
- [ ] Technique and transport tags are appropriate

## Build & Tests
- [ ] `go build ./...` succeeds
- [ ] Unit tests added in `tests/unit/`
- [ ] Integration tests added in `tests/integration/`
- [ ] `go test ./tests/...` passes

## Tab Completion & Help
- [ ] New module appears in `use` tab completion (automatic via registry)
- [ ] New module shows in `modules list` and `show modules`
- [ ] `search {service}` finds the new module
