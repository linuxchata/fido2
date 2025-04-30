# Overview
This repository provides a server-side implementation of the FIDO2 protocol, enabling secure passwordless authentication and multi-factor authentication (MFA) for web applications. It handles key FIDO2 operations, including credential registration and authentication, ensuring compliance with modern authentication standards.

# Usage
The following examples demonstrate how to implement FIDO2 authentication in your application.

## Server-side (ASP.NET Core Controllers)
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

## Client-side (JavaScript)
To complete the FIDO2 implementation, you need to add JavaScript code that communicates with the Web Authentication API (WebAuthn) in the browser. The WebAuthn API is part of the FIDO2 specification and provides the client-side functionality for secure authentication. Below you can find sample implementation for communication with WebAuthn:

- [fido2-attestation.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Portal.Fido2/wwwroot/js/fido2-attestation.js) - Handles the registration process using the Web Authentication API (navigator.credentials.create)
- [fido2-assertion.js](https://github.com/linuxchata/fido2/blob/main/src/Shark.Portal.Fido2/wwwroot/js/fido2-assertion.js) - Handles the authentication process using the Web Authentication API (navigator.credentials.get)

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
