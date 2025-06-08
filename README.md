# Overview
This repository provides a server-side implementation of the FIDO2 protocol, enabling secure passwordless authentication and multi-factor authentication (MFA) for web applications. It handles key FIDO2 operations, including credential registration and authentication, ensuring compliance with modern authentication standards.

## Supported Features
- **Attestation flow** for credentials registration
- **Assertion flow** for credentials verification
- **Supported attestation statement formats**:
  - Packed
  - TPM
  - Android Key
  - Android SafetyNet
  - FIDO U2F
  - None
  - Apple Anonymous
- **Built-in storage providers**:
  - Microsoft SQL Server
  - In-memory storage
 - **FIDO metadata service**

# Usage
The following examples demonstrate how to implement FIDO2 authentication in your application.

## Server side (ASP.NET Core Controllers)
The sample C# code below is designed for ASP.NET Core controllers.

### Attestation (registration)
1. Get creation options.
```csharp
[HttpPost("options")]
public async Task<IActionResult> Options(ServerPublicKeyCredentialCreationOptionsRequest request)
{
    var creationOptions = await _attestation.GetOptions(request.Map());
    var response = creationOptions.Map();
    HttpContext.Session.SetString("CreationOptions", JsonSerializer.Serialize(creationOptions));
    return Ok(response);
}
```

2. Create credential.
```csharp
[HttpPost("result")]
public async Task<IActionResult> Result(ServerPublicKeyCredentialAttestation request)
{
    var creationOptionsString = HttpContext.Session.GetString("CreationOptions");
    var creationOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(creationOptionsString!);
    await _attestation.Complete(request.Map(), creationOptions!);
    return Ok(ServerResponse.Create());
}
```

### Assertion (authentication)
1. Get request options.
```csharp
[HttpPost("options")]
public async Task<IActionResult> Options(ServerPublicKeyCredentialGetOptionsRequest request)
{
    var requestOptions = await _assertion.RequestOptions(request.Map());
    var response = requestOptions.Map();
    HttpContext.Session.SetString("RequestOptions", JsonSerializer.Serialize(requestOptions));
    return Ok(response);
}
```

2. Validate credential.
```csharp
[HttpPost("result")]
public async Task<IActionResult> Result(ServerPublicKeyCredentialAssertion request)
{
    var requestOptionsString = HttpContext.Session.GetString("RequestOptions");
    var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString!);
    await _assertion.Complete(request.Map(), requestOptions!);
    return Ok(ServerResponse.Create());
}
```

### Configuration
The server side can be customized using the following configuration options. You can set these options in an `appsettings.json` file.

| Option | Default | Description |
|-|-|-|
| `RelyingPartyId` |  | Valid domain string identifying the Relying Party on whose behalf a given registration or authentication ceremony is being performed. This is a critical parameter in the WebAuthn protocol. It defines the security scope within which credentials are valid. Therefore, careful selection is essential, as an incorrect or overly broad value can lead to unintended credential reuse or security vulnerabilities. |
| `RelyingPartyIdName` |  | Human-palatable identifier for the Relying Party, intended only for display. |
| `Origin` |  | Fully qualified origin of the Relying Party making the request, passed to the authenticator by the browser. |
| `Timeout` | `60000` | Time, in milliseconds, that the Relying Party is willing to wait for the call to complete.  |
| `AllowNoneAttestation` | `true` | Value indicating whether None attestation type is acceptable under Relying Party policy. [None attestation](https://www.w3.org/TR/webauthn-2/#none) is used when the authenticator doesn't have any attestation information available. |
| `AllowSelfAttestation` | `true` | Value indicating whether Self attestation type is acceptable under Relying Party policy. [Self attestation](https://www.w3.org/TR/webauthn-2/#self-attestation) is used when the authenticator doesn't have a dedicated attestation key pair or a vendor-issued certificate. |
| `EnableTrustedExecutionEnvironmentOnly` | `true` | Value indicating whether the Relying Party trusts only keys that are securely generated and stored in a Trusted Execution Environment (Android Key Attestation). |
| `EnableMetadataService` | `true` | Value indicating whether the Relying Party uses the Metadata Service to verify the attestation object. |
| `EnableStrictAuthenticatorVerification` | `false` | Value indicating whether the Relying Party requires strict verification of authenticators. If enabled, missing metadata for the authenticator would cause attestation to fail. |

| Option | Default | Description |
|-|-|-|
| `MetadataBlobLocation` | `https://mds3.fidoalliance.org/` | Location of the centralized and trusted source of information about FIDO authenticators (Metadata Service BLOB). |
| `RootCertificateLocationUrl` | `http://secure.globalsign.com/cacert/root-r3.crt` | Location of GlobalSign Root R3 for Metadata Service BLOB. |
| `MaximumTokenSizeInBytes` | `6291456` | Maximum token size in bytes that will be processed. This configuration is related to the Metadata Service BLOB size. |

Example `appsettings.json` file: [appsettings.Production.json](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Portal/appsettings.Production.json)

## Client side (JavaScript)
To complete the FIDO2 implementation, you need to add JavaScript code that communicates with the Web Authentication API (WebAuthn) in the browser. The WebAuthn API is part of the FIDO2 specification and provides the client-side functionality for secure authentication. Below you can find sample implementation for communication with WebAuthn:

- [fido2-attestation.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Portal/wwwroot/js/fido2-attestation.js) - Handles the registration process using the Web Authentication API (navigator.credentials.create)
- [fido2-assertion.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Portal/wwwroot/js/fido2-assertion.js) - Handles the authentication process using the Web Authentication API (navigator.credentials.get)

This JavaScript code bridges the browser's WebAuthn API with the server-side REST API endpoints provided by the ASP.NET Core controllers described above.

# Build Status
[![build](https://github.com/linuxchata/fido2/actions/workflows/build.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build.yml) [![nuget](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_core_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_core_packages.yml) [![nuget](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_models_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_models_packages.yml) [![nuget](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_inmemory_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_inmemory_packages.yml) [![nuget](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_sqlserver_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_sqlserver_packages.yml)

# Packages
| Package Name | Status |
|-|-|
| Shark.Fido2.Core | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Core.svg)](https://www.nuget.org/packages/Shark.Fido2.Core/) |
| Shark.Fido2.InMemory | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.InMemory.svg)](https://www.nuget.org/packages/Shark.Fido2.InMemory/) |
| Shark.Fido2.Models | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Models.svg)](https://www.nuget.org/packages/Shark.Fido2.Models/) |
| Shark.Fido2.SqlServer | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.SqlServer.svg)](https://www.nuget.org/packages/Shark.Fido2.SqlServer/) |

# FIDO Conformance Tests
All test cases successfully passed using the FIDO Conformance Tool.
![image](https://github.com/user-attachments/assets/993b3dc5-7600-4e4f-8176-a5bbff8aa4b7)

# Specification
## Web Authentication
- [Web Authentication: An API for accessing Public Key Credentials Level 2](https://www.w3.org/TR/webauthn-2/)
- [Server Requirements and Transport Binding Profile](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html)
- [Web Authentication: An API for accessing Public Key Credentials Level 3](https://www.w3.org/TR/webauthn-3/)

## Metadata Service
- [FIDO Metadata Service](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html)
- [FIDO Metadata Statement](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html)

# Tools
- [FIDO Alliance - Certification Conformance Test Tools](https://github.com/fido-alliance/conformance-test-tools-resources/tree/main)

# References
- [PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential)
