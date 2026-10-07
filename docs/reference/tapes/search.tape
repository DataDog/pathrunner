# VHS tape -> docs/reference/gifs/search.gif
# Category: AWS-free. Searches the module registry by keyword; no credentials,
# no AWS calls, no ~/.pathrunner state. Safe to render in CI.
# Render: vhs docs/reference/tapes/search.tape   (run from the repo root)

Output docs/reference/gifs/search.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"

Hide
Type "alias pathrunner='./pathrunner'"
Enter
Show

Type "pathrunner search lambda"
Enter
Sleep 4s
