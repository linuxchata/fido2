CREATE TABLE Credential (
    CredentialId VARBINARY(255) NOT NULL PRIMARY KEY,
    UserHandle VARBINARY(256) NOT NULL,
    Username NVARCHAR(256) NOT NULL,
    CredentialPublicKeyJson NVARCHAR(2048) NOT NULL,
    SignCount BIGINT NOT NULL,
    Transports NVARCHAR(50) NULL
);