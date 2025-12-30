using System.Security.Cryptography.X509Certificates;

namespace CertificateDemoAPI.Services
{
    public interface IDigitalSignatureService
    {

        // Sign document with certificate
        byte[] SignData(byte[] data, X509Certificate2 certificate, string algorithm = "SHA256");

        // Verify signature
        bool VerifyData(byte[] data, byte[] signature, X509Certificate2 certificate, string algorithm = "SHA256");

        // Create detached signature with metadata
        string CreateDetachedSignature(byte[] data, X509Certificate2 certificate, string algorithm = "SHA256");

        // Verify detached signature
        (bool isValid, string signer, DateTime signingTime) VerifyDetachedSignature(
            byte[] data, string detachedSignature);

        // Sign hash
        byte[] SignHash(byte[] hash, X509Certificate2 certificate, string algorithm = "SHA256");

        // Verify hash
        bool VerifyHash(byte[] hash, byte[] signature, X509Certificate2 certificate, string algorithm = "SHA256");
    }
}

