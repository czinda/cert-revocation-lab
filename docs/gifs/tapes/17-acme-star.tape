# Akamu ACME — STAR (RFC 8739)
Output docs/gifs/17-acme-star.mp4
Set FontSize 16
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 30ms
Set Shell "bash"

Type "# ACME STAR — akamu-rsa.cert-lab.local (RFC 8739)"
Enter
Sleep 1s
Type "grep -A4 '^\[star\]' configs/akamu/rsa-config.toml"
Enter
Sleep 3s
Type "# Short-lived certs that auto-renew. Requires local signing key —"
Enter
Type "# skipped in Dogtag RA mode (external signer)."
Enter
Sleep 3s
