# VHS tape -> docs/reference/gifs/identity-switch.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/ with two synthetic identities
# (starting-user, second-identity). Switches from starting-user to second-identity
# and then lists to confirm. No real credentials, no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/identity-switch.tape   (run from the repo root)

Output docs/reference/gifs/identity-switch.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 400
Set Padding 20
Set Theme "Dracula"

Type "./scripts/docs-sandbox.sh identity switch second-identity"
Enter
Sleep 4s
