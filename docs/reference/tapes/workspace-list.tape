# VHS tape -> docs/reference/gifs/workspace-list.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ (single "demo" workspace). No real
# credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/workspace-list.tape   (run from the repo root)

Output docs/reference/gifs/workspace-list.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 300
Set Padding 20
Set Theme "Dracula"

Type "./scripts/docs-sandbox.sh workspace list"
Enter
Sleep 4s
