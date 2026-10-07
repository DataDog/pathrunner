# VHS tape -> docs/reference/gifs/identity-show.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ with a synthetic starting-user
# identity (account 111111111111). No real credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/identity-show.tape   (run from the repo root)

Output docs/reference/gifs/identity-show.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 420
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Enter
Show

Type "pathrunner identity show"
Enter
Sleep 4s
