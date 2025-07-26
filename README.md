# Overview
This repository provides a server-side implementation of the WebAuthn standard that enables secure passwordless and multi-factor authentication (MFA) for web applications. It supports key WebAuthn operations – credential registration and authentication – ensuring compliance with the [WebAuthn Level 2 specification](https://www.w3.org/TR/webauthn-2/) (Web Authentication: An API for accessing Public Key Credentials Level 2).

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
- Supported cryptographic algorithms: ES256, EdDSA, ES384, ES512, PS256, PS384, PS512, ES256K, RS256, RS384, RS512, RS1
- **Built-in storage providers**:
  - Microsoft SQL Server
  - Amazon DynamoDB
  - In-memory storage
 - **FIDO metadata service**
 - Code samples and demo website

# Build Status
[![build](https://github.com/linuxchata/fido2/actions/workflows/build.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build.yml) [![NuGet](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_packages.yml)

# Packages
| Package Name | Status |
|-|-|
| Shark.Fido2.Core | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Core.svg)](https://www.nuget.org/packages/Shark.Fido2.Core/) |
| Shark.Fido2.DynamoDB | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.DynamoDB.svg)](https://www.nuget.org/packages/Shark.Fido2.DynamoDB/) |
| Shark.Fido2.InMemory | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.InMemory.svg)](https://www.nuget.org/packages/Shark.Fido2.InMemory/) |
| Shark.Fido2.Models | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Models.svg)](https://www.nuget.org/packages/Shark.Fido2.Models/) |
| Shark.Fido2.SqlServer | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.SqlServer.svg)](https://www.nuget.org/packages/Shark.Fido2.SqlServer/) |

# Usage
The following examples demonstrate how to implement passwordless authentication in your application. For complete reference and additional details, see the [full documentation](https://shark-fido2.com/Documentation).

## Server-side API (ASP.NET Core Controllers)
The sample C# code below is designed for ASP.NET Core controllers.

### Dependencies Registration
Registers both the credential store (in-memory or alternative) and the core dependencies.
```csharp
builder.Services.AddFido2InMemoryStore();
builder.Services.AddFido2(builder.Configuration);
```

### Server-side Configuration
The server side can be customized using the following configuration options. You can set these options in an `appsettings.json` file.

#### Core Configuration
| Option | Default | Description |
|-|-|-|
| `RelyingPartyId` |  | Valid domain string identifying the Relying Party on whose behalf a given registration or authentication ceremony is being performed. This is a critical parameter in the WebAuthn protocol. It defines the security scope within which credentials are valid. Therefore, careful selection is essential, as an incorrect or overly broad value can lead to unintended credential reuse or security vulnerabilities. |
| `RelyingPartyIdName` |  | Human-readable identifier for the Relying Party, intended only for display. |
| `Origins` |  | List of the fully qualified origins of the Relying Party making the request, passed to the authenticator by the browser. |
| `Timeout` | `60000` | Time, in milliseconds, that the Relying Party is willing to wait for the call to complete. |
| `AlgorithmsSet` | `Extended` | Set of the supported cryptographic algorithms. Possible values are `Required`, `Recommended` or `Extended` |
| `AllowNoneAttestation` | `true` | Value indicating whether None attestation type is acceptable under Relying Party policy. [None attestation](https://www.w3.org/TR/webauthn-2/#none) is used when the authenticator doesn't have any attestation information available. |
| `AllowSelfAttestation` | `true` | Value indicating whether Self attestation type is acceptable under Relying Party policy. [Self attestation](https://www.w3.org/TR/webauthn-2/#self-attestation) is used when the authenticator doesn't have a dedicated attestation key pair or a vendor-issued certificate. |
| `EnableTrustedExecutionEnvironmentOnly` | `true` | Value indicating whether the Relying Party trusts only keys that are securely generated and stored in a Trusted Execution Environment (relevant for Android Key Attestation). |
| `EnableMetadataService` | `true` | Value indicating whether the Relying Party uses the Metadata Service to verify the attestation object. |
| `EnableStrictAuthenticatorVerification` | `false` | Value indicating whether the Relying Party requires strict verification of authenticators. If enabled, missing metadata for the authenticator would cause attestation to fail. |

#### FIDO Metadata Service Configuration
| Option | Default | Description |
|-|-|-|
| `MetadataBlobLocation` | `https://mds3.fidoalliance.org/` | Location of the centralized and trusted source of information about FIDO authenticators (Metadata Service BLOB). |
| `RootCertificateLocationUrl` | `http://secure.globalsign.com/cacert/root-r3.crt` | Location of GlobalSign Root R3 certificate for Metadata Service BLOB. |
| `MaximumTokenSizeInBytes` | `6291456` | Maximum token size in bytes that will be processed. This configuration is related to the Metadata Service BLOB size. |

Example `appsettings.json` file: [appsettings.Production.json](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Sample/appsettings.Production.json)

### Attestation (registration)
Attestation controller
1. Get create options.
```csharp
[HttpPost("options")]
public async Task<IActionResult> Options(ServerPublicKeyCredentialCreationOptionsRequest request, CancellationToken cancellationToken)
{
    var createOptions = await _attestation.CreateOptions(request.Map(), cancellationToken);
    var response = createOptions.Map();
    HttpContext.Session.SetString("CreateOptions", JsonSerializer.Serialize(createOptions));
    return Ok(response);
}
```

2. Create credential.
```csharp
[HttpPost("result")]
public async Task<IActionResult> Result(ServerPublicKeyCredentialAttestation request, CancellationToken cancellationToken)
{
    var createOptionsString = HttpContext.Session.GetString("CreateOptions");
    var createOptions = JsonSerializer.Deserialize<PublicKeyCredentialCreationOptions>(createOptionsString!);
    await _attestation.Complete(request.Map(), createOptions!, cancellationToken);
    return Ok(ServerResponse.Create());
}
```

### Assertion (authentication)
Assertion controller
1. Get request options.
```csharp
[HttpPost("options")]
public async Task<IActionResult> Options(ServerPublicKeyCredentialGetOptionsRequest request, CancellationToken cancellationToken)
{
    var requestOptions = await _assertion.RequestOptions(request.Map(), cancellationToken);
    var response = requestOptions.Map();
    HttpContext.Session.SetString("RequestOptions", JsonSerializer.Serialize(requestOptions));
    return Ok(response);
}
```

2. Validate credential.
```csharp
[HttpPost("result")]
public async Task<IActionResult> Result(ServerPublicKeyCredentialAssertion request, CancellationToken cancellationToken)
{
    var requestOptionsString = HttpContext.Session.GetString("RequestOptions");
    var requestOptions = JsonSerializer.Deserialize<PublicKeyCredentialRequestOptions>(requestOptionsString!);
    await _assertion.Complete(request.Map(), requestOptions!, cancellationToken);
    return Ok(ServerResponse.Create());
}
```

## Client-side Integration
To finalize the implementation, you must incorporate JavaScript code that interacts with the browser's Web Authentication API. This API manages the client-side authentication process. The following is a sample implementation:

- [fido2-attestation.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Sample/wwwroot/js/fido2-attestation.js) handles the registration process using the Web Authentication API (`navigator.credentials.create`).
- [fido2-assertion.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Fido2.Sample/wwwroot/js/fido2-assertion.js) handles the authentication process using the Web Authentication API (`navigator.credentials.get`).

This JavaScript code binds the browser's Web Authentication API to the server-side REST API endpoints provided by the ASP.NET Core controllers described above. More information about the Web Authentication API is available on the MDN Web Docs site at [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) page.

# FIDO Conformance Tests
All test cases successfully passed using the FIDO Conformance Tool.
![image](https://github.com/user-attachments/assets/993b3dc5-7600-4e4f-8176-a5bbff8aa4b7)

## License
This project is licensed under the [BSD 3-Clause License](LICENSE).

# Contributing
See [Contributing](https://github.com/linuxchata/fido2/blob/main/CONTRIBUTING.md) for information about contributing to the project.

# Specification
## Introduction
- [An introduction to Web Authentication](https://webauthn.guide/)
- [Web Authentication Credential and Login Demo](https://webauthn.me/)
- [FIDO Alliance](https://fidoalliance.org/)

## Web Authentication
- [Web Authentication: An API for accessing Public Key Credentials Level 2](https://www.w3.org/TR/webauthn-2/)
- [Server Requirements and Transport Binding Profile](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-server-v2.0-rd-20180702.html)
- [Web Authentication: An API for accessing Public Key Credentials Level 3](https://www.w3.org/TR/webauthn-3/)
- [PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential)

## Metadata Service
- [FIDO Metadata Service](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html)
- [FIDO Metadata Statement](https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html)

# Tools
- [FIDO Alliance - Certification Conformance Test Tools](https://github.com/fido-alliance/conformance-test-tools-resources/tree/main)
