CREATE TABLE [Credential] (
    [CredentialId] VARBINARY(255) NOT NULL,
    [UserHandle] VARBINARY(64) NOT NULL,
    [UserName] NVARCHAR(64) NOT NULL,
    [UserDisplayName] NVARCHAR(256) NOT NULL,
    [CredentialPublicKeyJson] NVARCHAR(2048) NOT NULL,
    [SignCount] BIGINT NOT NULL,
    [Transports] NVARCHAR(50) NULL,
    [CreatedAt] DATETIME2 NOT NULL CONSTRAINT [DF_Credential_CreatedAt] DEFAULT GETUTCDATE(),
    [UpdatedAt] DATETIME2 NULL,
    [LastUsedAt] DATETIME2 NULL,
    CONSTRAINT [PK_Credential_CredentialId] PRIMARY KEY ([CredentialId])
);

CREATE NONCLUSTERED INDEX [IX_Credential_UserName] ON [dbo].[Credential] ([UserName])