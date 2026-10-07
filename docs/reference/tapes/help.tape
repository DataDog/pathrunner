# VHS tape -> docs/reference/gifs/help.gif
# Category: AWS-free. Needs only the built ./pathrunner binary; no credentials,
# no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/help.tape   (run from the repo root)

Output docs/reference/gifs/help.gif

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

Type "pathrunner --help"
Enter
Sleep 4s
