Shark WebAuthn library for .NET provides a server-side implementation of the WebAuthn standard, enabling secure passwordless and multi-factor authentication (MFA) for web applications. It supports key WebAuthn operations - credential registration and authentication - ensuring compliance with the WebAuthn Level 2 specification (Web Authentication: An API for accessing Public Key Credentials Level 2).

This package provides Amazon DynamoDB implementation for storing WebAuthn credentials.

Table name is `Credential` with partition key `cid` (credential identifier) and no sort key. A global secondary index named `UserNameIndex` uses `un` (username) as its partition key, with no sort key.