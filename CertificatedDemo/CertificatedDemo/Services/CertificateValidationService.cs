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
            try
            {
                if (certificate == null)
                {
                    _logger.LogWarning("Certificate is null");
                    return false;
                }

                // Check validity period
                if (DateTime.Now < certificate.NotBefore)
                {
                    _logger.LogWarning("Certificate {Subject} is not valid yet (Valid from: {NotBefore})",
                        certificate.Subject, certificate.NotBefore);
                    return false;
                }

                if (DateTime.Now > certificate.NotAfter)
                {
                    _logger.LogWarning("Certificate {Subject} has expired (Expired on: {NotAfter})",
                        certificate.Subject, certificate.NotAfter);
                    return false;
                }

                // For demo with OpenSSL-generated certificates, check if issued by our CA
                var caPath = "certificates/ca.crt"; // Updated path
                if (File.Exists(caPath))
                {
                    try
                    {
                        var rootCert = new X509Certificate2(caPath);

                        // Check if certificate is issued by our CA
                        if (certificate.Issuer.Contains("CertificatedDemo Root CA"))
                        {
                            _logger.LogInformation("Certificate {Subject} issued by CertificatedDemo Root CA",
                                certificate.Subject);
                            return true;
                        }
                        else if (certificate.Issuer == certificate.Subject)
                        {
                            _logger.LogInformation("Certificate {Subject} is self-signed", certificate.Subject);
                            // Accept self-signed for demo
                            return true;
                        }
                        else
                        {
                            _logger.LogWarning("Certificate {Subject} not issued by our CA", certificate.Subject);
                            // For demo, still accept it
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Error validating certificate against CA");
                        // Continue anyway for demo
                    }
                }
                else
                {
                    _logger.LogWarning("CA certificate not found at {Path}", caPath);
                }

                // Accept certificate for demo (since we're using self-signed/OpenSSL certs)
                _logger.LogInformation("Accepted certificate {Subject} for demo purposes", certificate.Subject);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Certificate validation failed");
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