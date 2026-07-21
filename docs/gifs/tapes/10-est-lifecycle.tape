# Kipuka EST — Full Certificate Lifecycle
Output docs/gifs/10-est-lifecycle.mp4
Set FontSize 16
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Type "# EST Full Lifecycle: Enroll → Verify → Revoke → Confirm"
Enter
Sleep 1s
Type "./lab est-enroll -d lifecycle-device -p rsa"
Enter
Sleep 8s
Type "./lab test -p rsa --scenario 'Certificate Private Key Compromise' 2>&1 | tail -10"
Enter
Sleep 12s
