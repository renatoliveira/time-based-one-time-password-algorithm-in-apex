# Apex Time-Based One-Time Password Algorithm

Based on [RFC 6238.](https://tools.ietf.org/html/rfc6238).

Key URI based on [Google Authenticator's](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

## Usage

When using the provided anonymous Apex sample in the scripts folder, the result would be something like this:

```
17:00:35.40 (52589659)|USER_DEBUG|[13]|DEBUG|otpauth://totp/TOTPInc:renato@totp.demo?secret=JBSWY3DPEB3W64TMMQQQ====&issuer=TOTPInc&algorithm=SHA1&period=30&digits=6
17:00:35.40 (53790153)|USER_DEBUG|[8]|DEBUG|Generating for step 328aca1
17:00:35.40 (56052233)|USER_DEBUG|[8]|DEBUG|Generating for step 328aca2
17:00:35.40 (57275182)|USER_DEBUG|[15]|DEBUG|(596192, 064211)
```

The first line contains the Key URI used by authenticator apps such as Authy and 1Password. It is literally the QR Code the user scans when adding a new 2FA method to their account.

The valid code for the current time period would be the first value of 596192. The second value, 064211, is the valid number for the next 30 seconds. This is due the fact that there can be synchronization issues between the client and the server.

Any string can be used as a secret (key) for the algorithm.
