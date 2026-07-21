# Kerberos — One Ticket, Two Protocols
Output docs/gifs/20-kerberos-dual.mp4
Set FontSize 15
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 25ms
Set Shell "bash"

Type "# One Kerberos Ticket → Two Enrollment Protocols"
Enter
Sleep 1s

Type `export KRB5_CONFIG=data/certs/rsa/krb5.conf && kinit -kt data/certs/rsa/certops.keytab certops@CERT-LAB.LOCAL && echo 'TGT: certops@CERT-LAB.LOCAL'`
Enter
Sleep 1500ms

Type "# Protocol 1: ACME EAB from akamu-rsa.cert-lab.local"
Enter
Type `curl -s --negotiate -u : http://akamu-rsa.cert-lab.local:8080/acme/eab | python3 -m json.tool`
Enter
Sleep 3s

Type "# Protocol 2: EST cert from kipuka-rsa.cert-lab.local + verify"
Enter
Type `bash scripts/demo-gssapi-enroll-verify.sh`
Enter
Sleep 10s
