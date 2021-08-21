# Encryption with thumbprint of certificate

## Use cases
- Different application decrypting the content.
- Not transmitted over wire.
- The certificate is rotated out of sync between encrypting and decrypting applications.

## Payload
The encryption with thumbprint includes the below contents in the payload.

![Thumbprint](https://www.plantuml.com/plantuml/proxy?fmt=svg&cache=no&src=https://raw.githubusercontent.com/dotnet-demos/Org.Security.Cryptography.X509Extensions/master/diagrams/thumbprint.puml)

## Cons
- If the content is transmitted over wire using encrypted auth information, attackers can intercept and replay using different HTTP or wire payload.