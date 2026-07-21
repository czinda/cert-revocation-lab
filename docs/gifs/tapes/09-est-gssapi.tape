# Kipuka EST — Kerberos SPNEGO Enrollment
Output docs/gifs/09-est-gssapi.mp4
Set FontSize 15
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 25ms
Set Shell "bash"

Type "# EST Kerberos Enrollment — kipuka-rsa.cert-lab.local (no OTP)"
Enter
Sleep 1s

Type "# Step 1: Obtain Kerberos ticket"
Enter
Type `export KRB5_CONFIG=data/certs/rsa/krb5.conf && kinit -kt data/certs/rsa/certops.keytab certops@CERT-LAB.LOCAL && klist`
Enter
Sleep 2s

Type "# Step 2: Enroll with SPNEGO and verify the certificate"
Enter
Type `bash scripts/demo-gssapi-enroll-verify.sh`
Enter
Sleep 10s
