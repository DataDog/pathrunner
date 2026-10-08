# VHS tape -> docs/reference/gifs/workspace-create.gif
# Category: Sandbox (local-state). Runs through scripts/docs-sandbox.sh, which
# seeds a throwaway HOME from docs/fixtures/. Creates a new workspace named
# "pentest-acme", then lists workspaces to show the result. No real credentials,
# no AWS calls. Safe for CI.
# Render: vhs docs/reference/tapes/workspace-create.tape   (run from the repo root)

Output docs/reference/gifs/workspace-create.gif

Set Shell "bash"
Set FontSize 16
Set Width 1100
Set Height 380
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Sleep 1500ms
Enter
Show

# Show both the create command and the resulting list so the GIF is self-contained.
# Two separate sandbox invocations — workspace state persists within the sandbox
# HOME for the lifetime of the shell session, but each docs-sandbox.sh call gets
# a fresh temp HOME. Use a single shell session via the REPL instead.
Type "pathrunner workspace create pentest-acme"
Sleep 1500ms
Enter
Sleep 4s
