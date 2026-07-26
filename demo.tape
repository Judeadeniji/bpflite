# Output file
Output demo.gif

# Set up the terminal appearance
Set FontSize 16
Set Width 1366
Set Height 768
Set Theme "Catppuccin Mocha"
Set WindowBar Rings

# Generate some background system activity for bpflite to catch!
Hide
Type "while true; do curl -s http://example.com > /dev/null; sleep 2; done &"
Enter
Type "while true; do cat /etc/passwd > /dev/null; sleep 2; done &"
Enter
Type "while true; do touch /tmp/bpflite_demo; rm /tmp/bpflite_demo; sleep 2; done &"
Enter
Type "clear"
Enter
Show

# Start the tool
Type "bin/bpflite trace all"
Enter
Sleep 4s

# 1. Feature: Network Tracing (TCP connects)
Type "s"
Sleep 1s
Type "/net"
Sleep 1s
Enter
Sleep 1s
Type "/"
Sleep 500ms
Type "curl"
Sleep 1s
Enter
Sleep 4s

# 2. Feature: File System Tracing (openat)
Type "s"
Sleep 1s
Type "/open"
Sleep 1s
Enter
Sleep 1s
Type "/"
Sleep 500ms
Type "cat"
Sleep 1s
Enter
Sleep 4s

# 3. Feature: Process Execution Tracing (execve)
Type "s"
Sleep 1s
Type "/exec"
Sleep 1s
Enter
Sleep 1s
Escape
Sleep 1s
Type "/"
Sleep 500ms
Type "sleep"
Sleep 1s
Enter
Sleep 4s

# Show details pane of an execution
Down@500ms 2
Sleep 3s

# Quit gracefully
Type "q"
Sleep 1s

# Cleanup background noise
Hide
Type "kill $(jobs -p)"
Enter
Show
