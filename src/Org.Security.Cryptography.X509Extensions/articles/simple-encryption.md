# Simple encryption

## Use cases
- Same application decrypting the content.
- Not transmitted over wire.
- The certificate is known to the decrypting application.

## Payload
The basic encryption includes the below contents in the payload.

![Simple](https://www.plantuml.com/plantuml/proxy?fmt=svg&cache=no&src=https://raw.githubusercontent.com/dotnet-demos/Org.Security.Cryptography.X509Extensions/master/diagrams/simple.puml)

## Cons
- If the certificate is rotated out of sync between the encrypting and decrypting applications, the decryption will fail.
- If the content is transmitted over wire using encrypted auth information, attackers can intercept and replay using different HTTP or wire payload.