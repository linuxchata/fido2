namespace Shark.Fido2.Core.Models
{
    /// <summary>
    /// Attestation Object Data
    /// https://www.w3.org/TR/webauthn-2/#attestation-object
    /// </summary>
    public sealed class AttestationObjectDataModel
    {
        /// <summary>
        /// An attestation statement format (fmt).
        /// </summary>
        public string? AttestationStatementFormat { get; set; }

        /// <summary>
        /// Attestation statement (attStmt).
        /// </summary>
        public object? AttestationStatement { get; set; }

        /// <summary>
        /// A byte array containing authenticator data (attStmt).
        /// </summary>
        public AuthenticatorDataModel? AuthenticatorData { get; set; }
    }
}
