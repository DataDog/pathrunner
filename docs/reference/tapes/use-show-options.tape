# VHS tape -> docs/reference/gifs/use-show-options.gif
# Category: Sandbox (local-state). Opens the REPL in the docs sandbox (synthetic
# fixtures, no real credentials, no AWS calls) and demonstrates the module
# selection workflow: use -> show options -> set an option -> show options again.
# This is the core "how to configure and run a module" pattern.
# Render: vhs docs/reference/tapes/use-show-options.tape   (run from the repo root)

Output docs/reference/gifs/use-show-options.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./scripts/docs-sandbox.sh'"
Enter
Show

# Start the REPL in the sandbox (no args = REPL mode, reads from synthetic fixtures).
Type "pathrunner"
Enter
Sleep 2s

# Select a module.
Type "use lambda-001"
Enter
Sleep 2s

# Show the options table.
Type "show options"
Enter
Sleep 2s

# Set a required option.
Type "set ROLE_ARN arn:aws:iam::111111111111:role/pl-demo-target-role"
Enter
Sleep 1s

# Show options again to confirm the value is set.
Type "show options"
Enter
Sleep 3s

Type "exit"
Enter
Sleep 1s
