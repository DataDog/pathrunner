# VHS tape -> docs/reference/gifs/show-payloads.gif
# Category: Sandbox (local-state). Opens the REPL in the docs sandbox and
# demonstrates browsing compatible payloads for a selected module. No real
# credentials, no AWS calls, no ~/.pathrunner state. Safe for CI.
# Render: vhs docs/reference/tapes/show-payloads.tape   (run from the repo root)

Output docs/reference/gifs/show-payloads.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 620
Set Padding 20
Set Theme "Dracula"

# Start the REPL in the sandbox.
Type "./scripts/docs-sandbox.sh"
Enter
Sleep 2s

# Select a module with multiple payloads.
Type "use lambda-001"
Enter
Sleep 2s

# List compatible payloads.
Type "show payloads"
Enter
Sleep 3s

Type "exit"
Enter
Sleep 1s
