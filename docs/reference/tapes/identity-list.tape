# VHS tape -> docs/reference/gifs/identity-list.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ (synthetic identities, fake accounts
# 111111111111 / 222222222222) and sets PATHRUNNER_WORKSPACE=demo. No real
# credentials, no AWS calls, operator's ~/.pathrunner untouched. Safe for CI.
# Render: vhs docs/reference/tapes/identity-list.tape   (run from the repo root)

Output docs/reference/gifs/identity-list.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 620
Set Padding 20
Set Theme "Dracula"

Type "./scripts/docs-sandbox.sh identity list"
Enter
Sleep 4s
