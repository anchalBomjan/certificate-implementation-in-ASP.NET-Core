using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CertificateDemoAPI.Services
{
    public class DigitalSignatureService:IDigitalSignatureService
    {
        private readonly ILogger<DigitalSignatureService> _logger;

        public DigitalSignatureService(ILogger<DigitalSignatureService> logger)
        {
            _logger = logger;
        }

        public byte[] SignData(byte[] data, X509Certificate2 certificate, string algorithm = "SHA256")
        {
            if (!certificate.HasPrivateKey)
                throw new UnauthorizedAccessException("Certificate does not have private key");

            using var rsa = certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate does not contain RSA private key");

            var hashAlgorithm = GetHashAlgorithmName(algorithm);

            // Create hash of data
            byte[] hash = ComputeHash(data, algorithm);

            // Sign the hash
            return rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        public bool VerifyData(byte[] data, byte[] signature, X509Certificate2 certificate, string algorithm = "SHA256")
        {
            using var rsa = certificate.GetRSAPublicKey()
                ?? throw new InvalidOperationException("Certificate does not contain RSA public key");

            var hashAlgorithm = GetHashAlgorithmName(algorithm);
            byte[] hash = ComputeHash(data, algorithm);

            return rsa.VerifyHash(hash, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        public string CreateDetachedSignature(byte[] data, X509Certificate2 certificate, string algorithm = "SHA256")
        {
            // Sign the data
            var signature = SignData(data, certificate, algorithm);

            // Get certificate info
            var certInfo = new CertificateInfo
            {
                RawData = Convert.ToBase64String(certificate.RawData),
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                Issuer = certificate.Issuer,
                SerialNumber = certificate.SerialNumber
            };


            // Create signed document
            var signedDocument = new SignedDocument
            {
                Version = "1.0",
                DocumentHash = Convert.ToBase64String(ComputeHash(data, algorithm)),
                Signature = Convert.ToBase64String(signature),
                Certificate = certInfo,
                Algorithm = algorithm,
                SigningTime = DateTime.UtcNow,
                DocumentSize = data.Length
            };

            return JsonSerializer.Serialize(signedDocument, new JsonSerializerOptions
            {
                WriteIndented = false
            });
        }

        public (bool isValid, string signer, DateTime signingTime) VerifyDetachedSignature(
            byte[] data, string detachedSignature)
        {
            try
            {
                var signedDoc = JsonSerializer.Deserialize<SignedDocument>(detachedSignature);
                if (signedDoc == null)
                    return (false, "Invalid signature format", DateTime.MinValue);

                // Load certificate from embedded data
                var certData = Convert.FromBase64String(signedDoc.Certificate.RawData);
                using var certificate = new X509Certificate2(certData);

                // Compute hash of provided data
                var computedHash = ComputeHash(data, signedDoc.Algorithm);
                var computedHashBase64 = Convert.ToBase64String(computedHash);

                // Verify document hash matches
                if (computedHashBase64 != signedDoc.DocumentHash)
                {
                    _logger.LogWarning("Document hash mismatch during verification");
                    return (false, signedDoc.Certificate.Subject, signedDoc.SigningTime);
                }

                // Convert signature back to bytes
                var signatureBytes = Convert.FromBase64String(signedDoc.Signature);

                // Verify signature
                var isValid = VerifyData(data, signatureBytes, certificate, signedDoc.Algorithm);

                return (isValid, signedDoc.Certificate.Subject, signedDoc.SigningTime);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying detached signature");
                return (false, "Error during verification", DateTime.MinValue);
            }
        }

        public byte[] SignHash(byte[] hash, X509Certificate2 certificate, string algorithm = "SHA256")
        {
            if (!certificate.HasPrivateKey)
                throw new UnauthorizedAccessException("Certificate does not have private key");

            using var rsa = certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate does not contain RSA private key");

            var hashAlgorithm = GetHashAlgorithmName(algorithm);
            return rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        public bool VerifyHash(byte[] hash, byte[] signature, X509Certificate2 certificate, string algorithm = "SHA256")
        {
            using var rsa = certificate.GetRSAPublicKey()
                ?? throw new InvalidOperationException("Certificate does not contain RSA public key");

            var hashAlgorithm = GetHashAlgorithmName(algorithm);
            return rsa.VerifyHash(hash, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        private HashAlgorithmName GetHashAlgorithmName(string algorithm)
        {
            return algorithm.ToUpper() switch
            {
                "SHA256" => HashAlgorithmName.SHA256,
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                "SHA1" => HashAlgorithmName.SHA1,
                _ => HashAlgorithmName.SHA256
            };
        }

        private byte[] ComputeHash(byte[] data, string algorithm)
        {
            return algorithm.ToUpper() switch
            {
                "SHA256" => SHA256.HashData(data),
                "SHA384" => SHA384.HashData(data),
                "SHA512" => SHA512.HashData(data),
                "SHA1" => SHA1.HashData(data),
                _ => SHA256.HashData(data)
            };
        }

        private class SignedDocument
        {
            public string Version { get; set; }
            public string DocumentHash { get; set; }
            public string Signature { get; set; }
            public CertificateInfo Certificate { get; set; }
            public string Algorithm { get; set; }
            public DateTime SigningTime { get; set; }
            public long DocumentSize { get; set; }
        }

        private class CertificateInfo
        {
            public string RawData { get; set; }
            public string Subject { get; set; }
            public string Thumbprint { get; set; }
            public string Issuer { get; set; }
            public string SerialNumber { get; set; }
        }


    }
}
