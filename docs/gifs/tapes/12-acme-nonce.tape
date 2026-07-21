# Akamu ACME — Replay Protection (Nonce)
Output docs/gifs/12-acme-nonce.mp4
Set FontSize 16
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Type "# ACME Nonce — akamu-rsa.cert-lab.local (RFC 8555 §7.2)"
Enter
Sleep 1s
Type "echo 'Request 1:' && curl -sI http://akamu-rsa.cert-lab.local:8080/acme/new-nonce | grep -i replay-nonce"
Enter
Sleep 2s
Type "echo 'Request 2:' && curl -sI http://akamu-rsa.cert-lab.local:8080/acme/new-nonce | grep -i replay-nonce"
Enter
Sleep 2s
Type "# Two requests, two different nonces — prevents replay attacks"
Enter
Sleep 2s
