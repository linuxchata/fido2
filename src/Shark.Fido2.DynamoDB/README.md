Shark WebAuthn authentication library for .NET provides a server-side implementation of the WebAuthn protocol, enabling secure passwordless and multi-factor authentication (MFA) for web applications. It supports key WebAuthn operations - credential registration and authentication - ensuring compliance with the WebAuthn Level 2 specification (Web Authentication: An API for accessing Public Key Credentials Level 2).

This package provides Amazon DynamoDB implementation for storing WebAuthn credentials.

Table name is `Credential`. Partition key name is `cid` (by credential identifier). Global Secondary Index name is `UserNameIndex`.