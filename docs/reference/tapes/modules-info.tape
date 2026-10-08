# VHS tape -> docs/reference/gifs/modules-info.gif
# Category: AWS-free. Shows static module metadata from the registry; no
# credentials, no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/modules-info.tape   (run from the repo root)

Output docs/reference/gifs/modules-info.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./pathrunner'"
Sleep 1500ms
Enter
Show

Type "pathrunner modules info lambda-001"
Sleep 1500ms
Enter
Sleep 4s
