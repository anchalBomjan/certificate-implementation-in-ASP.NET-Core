using System.Security.Cryptography.X509Certificates;

namespace CertificateDemoAPI.Services
{
    public interface ICertificateValidationService
    {
        bool ValidateCertificate(X509Certificate2 certificate);
        CertificateValidationResult ValidateCertificateWithDetails(X509Certificate2 certificate);
    }

    public class CertificateValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
        public List<string> Warnings { get; set; } = new List<string>();
        public string Subject { get; set; }
        public string Thumbprint { get; set; }
    }

}
