# VHS tape -> docs/reference/gifs/payloads.gif
# Category: AWS-free. Lists registered payloads from the in-process registry;
# no credentials, no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/payloads.tape   (run from the repo root)

Output docs/reference/gifs/payloads.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 820
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./pathrunner'"
Enter
Show

Type "pathrunner payloads"
Enter
Sleep 4s
