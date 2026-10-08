# VHS tape -> docs/reference/gifs/identity-current.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ with starting-user as the active
# identity. No real credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/identity-current.tape   (run from the repo root)

Output docs/reference/gifs/identity-current.gif

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 260
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Sleep 1500ms
Enter
Show

Type "pathrunner identity current"
Sleep 1500ms
Enter
Sleep 4s
