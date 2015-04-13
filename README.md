# github.com/therealmik/x509

This is a fork of Golang x509 that handles fairly broken certificates and has some extra support
for marshalling to JSON.

Do NOT use this for anything other than extracting data from (possibly broken) certificates.
I've removed safety features like enforcing critical extensions.

The Go LICENSE file applies to this code
