# VHS tape -> docs/reference/gifs/version.gif
# Category: AWS-free. Prints version metadata from the binary; no credentials,
# no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/version.tape   (run from the repo root)

Output docs/reference/gifs/version.gif

Set Shell "bash"
Set FontSize 16
Set Width 900
Set Height 220
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./pathrunner'"
Enter
Show

Type "pathrunner version"
Enter
Sleep 4s
