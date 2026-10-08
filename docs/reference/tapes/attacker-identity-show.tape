# VHS tape -> docs/reference/gifs/attacker-identity-show.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ (synthetic attacker identity in fake
# account 222222222222). No real credentials, no AWS calls, operator's
# ~/.pathrunner untouched. Safe for CI.
# Render: vhs docs/reference/tapes/attacker-identity-show.tape   (from repo root)

Output docs/reference/gifs/attacker-identity-show.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 560
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Sleep 1500ms
Enter
Show

Type "pathrunner attacker identity show"
Sleep 1500ms
Enter
Sleep 4s
