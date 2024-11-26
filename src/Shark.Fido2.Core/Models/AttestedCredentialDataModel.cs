﻿using System;

namespace Shark.Fido2.Core.Models
{
    /// <summary>
    /// Attested Credential Data
    /// </summary>
    public sealed class AttestedCredentialDataModel
    {
        public AttestedCredentialDataModel()
        {
            CredentialPublicKey = new CredentialPublicKeyModel();
        }

        /// <summary>
        /// The AAGUID of the authenticator
        /// </summary>
        public Guid AaGuid { get; set; }

        /// <summary>
        /// Credential ID
        /// </summary>
        public byte[] CredentialId { get; set; } = null!;

        /// <summary>
        /// The credential public key
        /// </summary>
        public CredentialPublicKeyModel CredentialPublicKey { get; set; } = null!;
    }
}