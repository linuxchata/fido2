# Overview
This repository provides a server-side implementation of the FIDO2 protocol, enabling secure passwordless authentication and multi-factor authentication (MFA) for web applications. It handles key FIDO2 operations, including credential registration and authentication, ensuring compliance with modern authentication standards. Designed for scalability and security, this implementation is ideal for integrating FIDO2-based authentication into server-side applications.

# Build Status
| Build server | Target |  Status |
|-|-|-|
| GitHub Actions | Build | [![build](https://github.com/linuxchata/fido2/actions/workflows/build.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build.yml) |
| GitHub Actions | NuGet | [![nuget](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_packages.yml/badge.svg)](https://github.com/linuxchata/fido2/actions/workflows/build_nuget_packages.yml) |

# Packages
| Package Source | Package Name | Status |
|-|-|-|
| NuGet | Shark.Fido2.Core | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Core.svg)](https://www.nuget.org/packages/Shark.Fido2.Core/) |
| NuGet | Shark.Fido2.InMemory | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.InMemory.svg)](https://www.nuget.org/packages/Shark.Fido2.InMemory/) |
| NuGet | Shark.Fido2.Models | [![NuGet](https://img.shields.io/nuget/v/Shark.Fido2.Models.svg)](https://www.nuget.org/packages/Shark.Fido2.Models/) |

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
