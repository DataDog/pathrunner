# VHS tape -> docs/reference/gifs/modules-status.gif
# Category: AWS-free. Reads module status flags from ~/.pathrunner/module-status.json;
# no credentials, no AWS calls. Runs with empty status (no prior test runs) so the
# table shows all modules in their default untested state. Safe to render in CI.
# Render: vhs docs/reference/tapes/modules-status.tape   (run from the repo root)

Output docs/reference/gifs/modules-status.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 820
Set Padding 20
Set Theme "Dracula"

Type "./pathrunner modules status"
Enter
Sleep 4s
