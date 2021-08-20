
| Area          |      Badges  |
|:--------------|:-------------|
| Build         | ![.Net workflow](https://github.com/dotnet-demos/Org.Security.Cryptography.X509Extensions/actions/workflows/dotnet.yml/badge.svg) |
| Code          | ![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/dotnet-demos/Org.Security.Cryptography.X509Extensions) ![GitHub repo size](https://img.shields.io/github/repo-size/dotnet-demos/Org.Security.Cryptography.X509Extensions) [![](https://tokei.rs/b1/github/dotnet-demos/Org.Security.Cryptography.X509Extensions)](https://github.com/dotnet-demos/Org.Security.Cryptography.X509Extensions) |
| Code Quality  | [![Maintainability](https://api.codeclimate.com/v1/badges/b64e91057b6c905e0347/maintainability)](https://codeclimate.com/github/dotnet-demos/Org.Security.Cryptography.X509Extensions/maintainability) |
| Test          | [![codecov](https://codecov.io/gh/dotnet-demos/Org.Security.Cryptography.X509Extensions/branch/master/graph/badge.svg?token=AS2FV3ACUI)](https://codecov.io/gh/dotnet-demos/Org.Security.Cryptography.X509Extensions) |

# Org.Security.Cryptography.X509Extensions
`X509Certificate2` Extensions for Encrypting and Signing using X509 certs.

# Getting started

- Clone or download the repo
- Compile Org.Security.Cryptography.X509Extensions.csproj to get the assembly.
- Refer the assembly in your project.

## Usage (Encryption)

 ```C#
     var x509Certificate = GetCertificateUsingYourWay(); // This certificate doesn't need to have private key.
     Stream yourStreamToEncrypt = GetYourStreamToEncrypt();
     var encryptedStream = new MemoryStream();
     x509Certificate.EncryptStream(yourStreamToEncrypt,encryptedStream);  
 ```
    
## Usage (Decryption)
 
 ```C#
     var x509Certificate = GetCertificateWithPrivateKeyUsingYourWay();
     Stream yourStreamToDecrypt = GetYourStreamToDecrypt();
     var decryptedStream = new MemoryStream();
     x509Certificate.DecryptStream(yourStreamToDecrypt, decryptedStream);  
 ```

# Running tests

Use `dotnet test` command or use the "Test Explorer" windows of Visual Studio.

In order to view coverage, use any of the below methods.

## Commandline

Below command has codecoverage threshold 100. It will fail as of now.

`dotnet test "src/UnitTests/UnitTests.csproj" --framework Net5.0 /p:CollectCoverage=true /p:CoverletOutputFormat=opencover /p:Threshold=100 /p:ThresholdType=line /p:Exclude="[*]X509.EnduranceTest.Shared*"`

It is excluding the shared test library.

## Visual Studio

Use the "Run Coverlet Report" extension as mentioned [here](https://www.code4it.dev/blog/code-coverage-vs-2019-coverlet)