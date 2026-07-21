# Unified Revocation — Protocol-Agnostic
Output docs/gifs/21-unified-revocation.mp4
Set FontSize 16
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Type "# Unified Revocation — Issue via EST, Revoke via Dogtag"
Enter
Sleep 1s
Type "./lab est-enroll -d revoke-target -p rsa 2>&1 | tail -3"
Enter
Sleep 6s
Type "# Revoke with keyCompromise reason"
Enter
Type "./lab test -p rsa --scenario 'Certificate Private Key Compromise' 2>&1 | tail -10"
Enter
Sleep 12s
