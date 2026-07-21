# Akamu ACME — Kerberos EAB → Account + Certificate (RFC 8555 §7.3.4)
Output docs/gifs/15-acme-eab.mp4
Set FontSize 15
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 25ms
Set Shell "bash"

Type "# ACME Kerberos EAB — akamu-rsa.cert-lab.local (RFC 8555 §7.3.4)"
Enter
Sleep 1s

Type "# Step 1: Obtain Kerberos ticket"
Enter
Type `export KRB5_CONFIG=data/certs/rsa/krb5.conf && kinit -kt data/certs/rsa/certops.keytab certops@CERT-LAB.LOCAL && klist`
Enter
Sleep 2s

Type "# Step 2: Fetch EAB credentials, issue cert, verify"
Enter
Type `bash scripts/demo-eab-enroll-verify.sh`
Enter
Sleep 20s
