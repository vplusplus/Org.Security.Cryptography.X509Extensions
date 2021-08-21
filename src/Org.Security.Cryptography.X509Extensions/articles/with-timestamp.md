# Encryption with timestamp of encryption

## Use cases
- Different application decrypting the content.
- Transmitted over wire as authentication.
- The certificate is rotated out of sync between encrypting and decrypting applications.

## Payload
The encryption with timestamp includes the below contents in the payload.

![timestamp](https://www.plantuml.com/plantuml/proxy?fmt=svg&cache=no&src=https://raw.githubusercontent.com/dotnet-demos/Org.Security.Cryptography.X509Extensions/master/diagrams/timestamp.puml)

## Cons
- The time to decrypt may be little more.