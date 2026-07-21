# RA Architecture — Two Protocols, One CA
Output docs/gifs/18-ra-architecture.mp4
Set FontSize 16
Set Width 1200
Set Height 800
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Type "# Registration Authority Architecture — Two Protocols, One CA"
Enter
Sleep 1s
Type "echo '=== Akamu (ACME) signer ===' && grep -A3 'ca.signer' configs/akamu/rsa-config.toml | head -4"
Enter
Sleep 2s
Type "echo '=== Kipuka (EST) backend ===' && grep -A3 '^\[dogtag\]' configs/kipuka/rsa-config.toml | head -4"
Enter
Sleep 2s
Type "echo '=== Shared agent cert ===' && openssl x509 -in data/certs/rsa/dogtag/agent.pem -noout -subject -issuer 2>/dev/null"
Enter
Sleep 3s
