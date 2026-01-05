using CertificatedDemo.Models;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificatedDemo.Services
{
    public class CertificateValidationService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<CertificateValidationService> _logger;

        public CertificateValidationService(IConfiguration configuration, ILogger<CertificateValidationService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public bool ValidateCertificate(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                _logger.LogWarning("Client certificate is null.");
                return false;
            }

            _logger.LogInformation("Validating client certificate: {Subject}", certificate.Subject);

            // 1. Check time validity
            if (DateTime.UtcNow < certificate.NotBefore || DateTime.UtcNow > certificate.NotAfter)
            {
                _logger.LogWarning("Certificate is outside its validity period. Valid from {NotBefore} to {NotAfter}.",
                    certificate.NotBefore, certificate.NotAfter);
                return false;
            }

            // 2. Check against custom CA
            var caPath = "certificates/ca.crt";
            if (!File.Exists(caPath))
            {
                _logger.LogError("Root CA certificate not found at {Path}. Cannot validate certificate chain.", caPath);
                return false; // Fail validation if CA is missing
            }

            try
            {
                var rootCaCert = new X509Certificate2(caPath);
                using var chain = new X509Chain();
                chain.ChainPolicy.ExtraStore.Add(rootCaCert);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // No revocation for demo
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;


                bool isValid = chain.Build(certificate);

                if (!isValid)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        _logger.LogWarning("Chain status: {Status}, {StatusInformation}", status.Status, status.StatusInformation.Trim());
                    }
                    _logger.LogWarning("Certificate chain validation failed for {Subject}.", certificate.Subject);
                    return false;
                }

                // Check if the chain is rooted in our custom CA
                var isTrusted = chain.ChainElements
                                     .Cast<X509ChainElement>()
                                     .Any(elem => elem.Certificate.Thumbprint == rootCaCert.Thumbprint);

                if (!isTrusted)
                {
                    _logger.LogWarning("Certificate {Subject} is not trusted by our custom CA.", certificate.Subject);
                    return false;
                }

                _logger.LogInformation("Certificate {Subject} successfully validated against custom CA.", certificate.Subject);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An error occurred during certificate chain validation.");
                return false;
            }
        }

        private bool HasEnhancedKeyUsage(X509Certificate2 certificate, string oid)
        {
            var enhancedKeyUsage = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (enhancedKeyUsage != null)
            {
                return enhancedKeyUsage.EnhancedKeyUsages.OfType<Oid>()
                    .Any(e => e.Value == oid);
            }
            return false;
        }

        public List<System.Security.Claims.Claim> GetClaimsFromCertificate(X509Certificate2 certificate)
        {
            var claims = new List<System.Security.Claims.Claim>
            {
                new("certificate.subject", certificate.Subject),
                new("certificate.issuer", certificate.Issuer),
                new("certificate.thumbprint", certificate.Thumbprint ?? ""),
                new("certificate.serialnumber", certificate.SerialNumber),
                new("certificate.validfrom", certificate.NotBefore.ToString("o")),
                new("certificate.validto", certificate.NotAfter.ToString("o")),
                new("certificate.valid", "true"),
                new("auth_method", "certificate")
            };

            // Extract certificate purposes from enhanced key usage
            var enhancedKeyUsage = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (enhancedKeyUsage != null)
            {
                foreach (var oid in enhancedKeyUsage.EnhancedKeyUsages.OfType<Oid>())
                {
                    var purpose = oid.FriendlyName ?? oid.Value;
                    claims.Add(new("certificate.purpose", purpose));

                    // Map specific OIDs to permissions
                    if (oid.Value == "1.3.6.1.5.5.7.3.2") // Client Authentication
                    {
                        claims.Add(new(System.Security.Claims.ClaimTypes.Role, "CertificateUser"));
                        claims.Add(new("Permission", Permissions.CertificatesView));
                    }
                    else if (oid.Value == "1.3.6.1.5.5.7.3.3") // Code Signing
                    {
                        claims.Add(new("Permission", Permissions.CodeSign));
                    }
                    else if (oid.Value == "1.3.6.1.5.5.7.3.4") // Email Protection
                    {
                        claims.Add(new("Permission", Permissions.DocumentSign));
                    }
                    else if (oid.Value == "1.3.6.1.5.5.7.3.1") // Server Authentication
                    {
                        claims.Add(new(System.Security.Claims.ClaimTypes.Role, "Server"));
                    }
                }
            }

            // Add roles based on certificate subject (from your OpenSSL generation)
            if (certificate.Subject.Contains("CertificatedDemo Root CA", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "Admin"));
                claims.Add(new("Permission", Permissions.CertificatesManage));
            }
            else if (certificate.Subject.Contains("CertificatedDemo Client", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "CertificateUser"));
                claims.Add(new("Permission", Permissions.CertificatesView));
                claims.Add(new("Permission", Permissions.ProductsView));
            }
            else if (certificate.Subject.Contains("Document Signing Certificate", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "DocumentSigner"));
                claims.Add(new("Permission", Permissions.DocumentSign));
            }
            else if (certificate.Subject.Contains("Code Signing Certificate", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "CodeSigner"));
                claims.Add(new("Permission", Permissions.CodeSign));
            }
            else if (certificate.Subject.Contains("localhost", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "Server"));
            }
            else if (certificate.Subject.Contains("Admin", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "Admin"));
                claims.Add(new("Permission", Permissions.CertificatesManage));
            }
            else if (certificate.Subject.Contains("Manager", StringComparison.OrdinalIgnoreCase))
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "Manager"));
                claims.Add(new("Permission", Permissions.ProductsView));
                claims.Add(new("Permission", Permissions.ProductsCreate));
                claims.Add(new("Permission", Permissions.ProductsEdit));
            }
            else
            {
                claims.Add(new(System.Security.Claims.ClaimTypes.Role, "User"));
                claims.Add(new("Permission", Permissions.ProductsView));
            }

            return claims;
        }
    }
}