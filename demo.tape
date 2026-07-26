# Output file
Output demo.gif

# Set up the terminal appearance
Set FontSize 16
Set Width 1366
Set Height 768
Set Theme "Catppuccin Mocha"
Set WindowBar Rings

# Start the tool
Type "bin/bpflite trace all"
Enter
Sleep 4s

# Show details pane updating as we scroll
Down@500ms 3
Sleep 2s

# Open the new switch modal
Type "s"
Sleep 1s

# Navigate to 'Open' tracer
Down@500ms 2
Sleep 1s
Enter
Sleep 3s

# Filter by a common process
Type "/"
Sleep 500ms
Type "systemd"
Sleep 2s
Enter
Sleep 2s

# Clear filter
Type "/"
Sleep 500ms
Backspace 7
Enter
Sleep 2s

# Switch to Net tracer using fuzzy find in the modal
Type "s"
Sleep 1s
Type "/net"
Sleep 1s
Enter
Sleep 4s

# Quit gracefully
Type "q"
Sleep 1s
