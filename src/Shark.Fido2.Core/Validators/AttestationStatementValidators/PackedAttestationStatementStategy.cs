using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Shark.Fido2.Core.Abstractions.Validators.AttestationStatementValidators;
using Shark.Fido2.Core.Enums;
using Shark.Fido2.Core.Results;
using Shark.Fido2.Domain;
using Shark.Fido2.Domain.Mappers;

namespace Shark.Fido2.Core.Validators.AttestationStatementValidators
{
    /// <summary>
    /// 8.2. Packed Attestation Statement Format
    /// </summary>
    internal class PackedAttestationStatementStategy : IAttestationStatementStategy
    {
        public ValidatorInternalResult Validate(
            AttestationObjectData attestationObjectData,
            ClientData clientData,
            PublicKeyCredentialCreationOptions creationOptions)
        {
            var attestationStatement = attestationObjectData.AttestationStatement;
            if (attestationStatement == null)
            {
                throw new ArgumentNullException(nameof(attestationStatement));
            }

            if (!(attestationStatement is Dictionary<string, object> attestationStatementDict))
            {
                throw new ArgumentNullException(nameof(attestationStatement), "Attestation statement cannot be read");
            }

            if (!attestationStatementDict.TryGetValue("alg", out var algorithm) || !(algorithm is int))
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm cannot be read");
            }

            // Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.
            var credentialPublicKey = attestationObjectData.AuthenticatorData!.AttestedCredentialData.CredentialPublicKey;
            if (credentialPublicKey.Algorithm != (int)algorithm)
            {
                return ValidatorInternalResult.Invalid("Attestation statement algorithm mismatch");
            }

            if (!attestationStatementDict.TryGetValue("sig", out var signature) || !(signature is byte[]))
            {
                return ValidatorInternalResult.Invalid("Attestation statement signature cannot be read");
            }

            // Verify that sig is a valid signature over the concatenation of authenticatorData and
            // clientDataHash using the credential public key with alg.
            var concatenatedData = GetConcatenatedData(
                attestationObjectData.AuthenticatorRawData,
                clientData.ClientDataHash);

            if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Rsa)
            {
                using var rsa = RSA.Create(new RSAParameters
                {
                    Modulus = credentialPublicKey.Modulus,
                    Exponent = credentialPublicKey.Exponent,
                });

                var algorithmDetails = RsaKeyTypeMapper.Get(credentialPublicKey.Algorithm.Value);

                var isValid = rsa.VerifyData(
                    concatenatedData,
                    (byte[])signature,
                    algorithmDetails.HashAlgorithmName,
                    algorithmDetails.Padding);

                return ValidatorInternalResult.Valid();
            }
            else if (credentialPublicKey.KeyType == (int)KeyTypeEnum.Ec2)
            {
                using var ecdsa = ECDsa.Create(new ECParameters
                {
                    Q = new ECPoint
                    {
                        X = credentialPublicKey.XCoordinate,
                        Y = credentialPublicKey.YCoordinate,
                    },
                    Curve = ECCurve.NamedCurves.nistP256, // https://www.rfc-editor.org/rfc/rfc9053.html#section-7.1
                });

                var isValid = ecdsa.VerifyData(concatenatedData, (byte[])signature, HashAlgorithmName.SHA256);

                return ValidatorInternalResult.Valid();
            }

            return ValidatorInternalResult.Invalid("Invalid signature");
        }

        private static byte[] GetConcatenatedData(byte[] authenticatorData, byte[] clientDataHash)
        {
            var concatenatedData = new byte[authenticatorData.Length + clientDataHash.Length];
            Buffer.BlockCopy(authenticatorData, 0, concatenatedData, 0, authenticatorData.Length);
            Buffer.BlockCopy(clientDataHash, 0, concatenatedData, authenticatorData.Length, clientDataHash.Length);

            return concatenatedData;
        }
    }
}
