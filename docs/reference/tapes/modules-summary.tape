# VHS tape -> docs/reference/gifs/modules-summary.gif
# Category: AWS-free. Shows module coverage summary table from the registry; no
# credentials, no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/modules-summary.tape   (run from the repo root)

Output docs/reference/gifs/modules-summary.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Dracula"

Type "./pathrunner modules summary"
Enter
Sleep 4s
