# VHS tape -> docs/reference/gifs/attacker-listener-status.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/. The listener is not running in the
# fixture, so the output shows the "stopped" state — which is the expected view
# before starting one. No real credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/attacker-listener-status.tape   (from repo root)

Output docs/reference/gifs/attacker-listener-status.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 300
Set Padding 20
Set Theme "Dracula"

Type "./scripts/docs-sandbox.sh attacker listener status"
Enter
Sleep 4s
