# VHS tape -> docs/reference/gifs/attacker-infra-status.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/. No infra is deployed in the fixture,
# so the output shows the "not deployed" state — the expected view before running
# `attacker infra ec2 create`. No real credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/attacker-infra-status.tape   (from repo root)

Output docs/reference/gifs/attacker-infra-status.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 320
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Enter
Show

Type "pathrunner attacker infra status"
Enter
Sleep 4s
