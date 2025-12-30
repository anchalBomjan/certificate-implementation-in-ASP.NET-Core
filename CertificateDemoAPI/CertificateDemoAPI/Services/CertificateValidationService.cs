using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateDemoAPI.Services
{
    public class CertificateValidationService:ICertificateValidationService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<CertificateValidationService> _logger;

        public CertificateValidationService(
            IConfiguration configuration,
            ILogger<CertificateValidationService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public bool ValidateCertificate(X509Certificate2 certificate)
        {
            var result = ValidateCertificateWithDetails(certificate);
            return result.IsValid;
        }

        public CertificateValidationResult ValidateCertificateWithDetails(X509Certificate2 certificate)
        {
            var result = new CertificateValidationResult
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint
            };

            // Check if certificate is not null
            if (certificate == null)
            {
                result.Errors.Add("Certificate is null");
                return result;
            }

            // Check validity period
            if (_configuration.GetValue<bool>("CertificateValidation:RequireValidPeriod", true))
            {
                var now = DateTime.Now;
                if (now > certificate.NotAfter)
                    result.Errors.Add($"Certificate expired on {certificate.NotAfter}");
                if (now < certificate.NotBefore)
                    result.Errors.Add($"Certificate not valid until {certificate.NotBefore}");
            }

            // Check thumbprint against allowed list
            var allowedThumbprints = _configuration.GetSection("AllowedClientCertificates")
                .Get<string[]>() ?? Array.Empty<string>();

            if (allowedThumbprints.Any() &&
                !allowedThumbprints.Contains(certificate.Thumbprint, StringComparer.OrdinalIgnoreCase))
            {
                result.Warnings.Add($"Certificate thumbprint {certificate.Thumbprint} not in allowed list");
            }

            // Check key usage
            if (_configuration.GetValue<bool>("CertificateValidation:RequireClientAuthEKU", true))
            {
                var ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>();
                if (ekuExtensions.Any())
                {
                    var eku = ekuExtensions.First();
                    var clientAuthOid = new Oid("1.3.6.1.5.5.7.3.2");

                    if (!eku.EnhancedKeyUsages.Cast<Oid>().Any(oid =>
                        oid.Value == clientAuthOid.Value))
                    {
                        result.Warnings.Add("Certificate does not have Client Authentication EKU");
                    }
                }
            }

            // Check for digital signature key usage
            var keyUsageExtensions = certificate.Extensions.OfType<X509KeyUsageExtension>();
            if (keyUsageExtensions.Any())
            {
                var keyUsage = keyUsageExtensions.First();
                if (!keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature))
                {
                    result.Warnings.Add("Certificate does not have Digital Signature key usage");
                }
            }

            // Log validation
            _logger.LogInformation("Certificate validation for {Subject}: {IsValid}",
                certificate.Subject, result.Errors.Count == 0);

            result.IsValid = result.Errors.Count == 0;
            return result;
        }


    }
}
