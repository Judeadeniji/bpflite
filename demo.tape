# Output file
Output demo.gif

# Set up the terminal appearance
Set FontSize 16
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"

# Start the tool
Type "bin/bpflite trace exec"
Enter
Sleep 5s

# Simulate typing a filter to demonstrate the UI features
Type "/curl"
Sleep 3s
Enter
Sleep 3s

# Clear the filter
Type "/"
Sleep 1s
Backspace 4
Enter
Sleep 3s
