# Contributing to Shark WebAuthn .NET library
Thank you for your interest in contributing to the Shark WebAuthn .NET library.

This document outlines how to get started, coding conventions, and how to submit issues or changes.

## Getting Started
1. **Fork** the repository on GitHub.
2. In your fork, click the **<> Code** button above the list of files.
3. Copy the URL for the repository.
4. **Clone** your fork:

   `git clone https://github.com/YOUR-USERNAME/fido2.git`

   `cd fido2/src`

5. **Build the project**:

   `dotnet build`

6. **Run tests**:

   `dotnet test`

## Code Guidelines
- Follow standard .NET/C# coding practices.
- Keep logic clear and modular.
- Write unit tests for new features and bug fixes.

## Submitting Changes
- Create a new branch:

   `git checkout -b feature/your-feature-name`

- Commit message should be concise and follow this format:
  - Add support for XYZ
  - Handle null case in ABC
  - Clarify usage in README
- Open a pull request with a clear title and description.
- Link to a related issue.

## Reporting Issues
Please include:
- Steps to reproduce.
- Expected vs actual behavior.
- Environment details (OS, browser, authenticator and mobile device if relevant).

Open issue via: https://github.com/linuxchata/fido2/issues

## Security
If you find a security issue, do **not** open a public issue. Instead, email: security@shark-fido2.com

Thanks again for helping improve this project!
