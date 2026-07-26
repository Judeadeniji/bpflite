# Output file
Output demo.gif

# Set up the terminal appearance
Set FontSize 15
Set Width 1366
Set Height 768
Set Theme "Catppuccin Mocha"
Set WindowBar Rings

# Start the tool
Type "sudo bin/bpflite trace all"
Enter
Sleep 3s

# Navigate to show the bottom details pane updating dynamically
Down@400ms 4
Sleep 2s
Up@400ms 2
Sleep 1s

# 1. Show off the main table filtering
Type "/"
Sleep 500ms
Type "systemd"
Sleep 1s
Enter
Sleep 3s

# Clear the filter instantly using the new Esc shortcut!
Escape
Sleep 2s

# 2. Show the Tracer Switch Modal
Type "s"
Sleep 1s

# Navigate down with j/k or arrows
Down@500ms 2
Sleep 1s
Enter
Sleep 3s

# 3. Open the modal again to show fuzzy-finding
Type "s"
Sleep 1s
Type "/"
Sleep 500ms
Type "net"
Sleep 1s

# Cancel the filter using Esc to return to normal modal navigation
Escape
Sleep 1s

# Manually navigate to the Exec tracer and select it
Up@400ms 2
Sleep 1s
Enter
Sleep 3s

# Quit gracefully
Type "q"
Sleep 1s
