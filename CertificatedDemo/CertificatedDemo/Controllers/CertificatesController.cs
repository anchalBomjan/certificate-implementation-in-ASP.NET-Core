using CertificatedDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificatedDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class CertificatesController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly CertificateValidationService _certificateService;
        private readonly ILogger<CertificatesController> _logger;

        public CertificatesController(
            IConfiguration configuration,
            CertificateValidationService certificateService,
            ILogger<CertificatesController> logger)
        {
            _configuration = configuration;
            _certificateService = certificateService;
            _logger = logger;
        }

        [HttpGet("info")]
        [AllowAnonymous]
        public IActionResult GetCertificateInfo()
        {
            var certificates = new Dictionary<string, object>();

            // Load and display all certificates
            var certFiles = new[]
            {
            new { Name = "Root CA", Path = "ca.crt", Password = (string?)null },
            new { Name = "SSL/TLS", Path = "ssl.pfx", Password = "ServerPass123!" },
            new { Name = "Client mTLS", Path = "client.pfx", Password = "ClientPass123!" },
            new { Name = "Document Signing", Path = "doc.pfx", Password = "DocPass123!" },
            new { Name = "Code Signing", Path = "code.pfx", Password = "CodePass123!" }
        };

            foreach (var certFile in certFiles)
            {
                try
                {
                    var cert = certFile.Password == null
                        ? new X509Certificate2(certFile.Path)
                        : new X509Certificate2(certFile.Path, certFile.Password);

                    certificates[certFile.Name] = new
                    {
                        Subject = cert.Subject,
                        Issuer = cert.Issuer,
                        Thumbprint = cert.Thumbprint,
                        SerialNumber = cert.SerialNumber,
                        NotBefore = cert.NotBefore,
                        NotAfter = cert.NotAfter,
                        HasPrivateKey = cert.HasPrivateKey,
                        SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName,
                        KeyAlgorithm = cert.GetKeyAlgorithm(),
                        KeySize = GetKeySize(cert),
                        Purposes = GetEnhancedKeyUsages(cert)
                    };
                }
                catch (Exception ex)
                {
                    certificates[certFile.Name] = new { Error = ex.Message };
                }
            }

            return Ok(new
            {
                Timestamp = DateTime.UtcNow,
                Certificates = certificates,
                Configuration = new
                {
                    RequiresClientCertificate = _configuration.GetValue<bool>("CertificateSettings:ClientCertificate:Required"),
                    DocumentSigningEnabled = _configuration.GetValue<bool>("CertificateSettings:DocumentCertificate:Enabled"),
                    CodeSigningEnabled = _configuration.GetValue<bool>("CertificateSettings:CodeCertificate:Enabled")
                }
            });
        }

        [HttpGet("validate")]
        [Authorize(Policy = "RequireCertificatesView")]
        public IActionResult ValidateCertificate()
        {
            var clientCert = HttpContext.Connection.ClientCertificate;

            if (clientCert == null)
                return BadRequest(new { message = "No client certificate provided" });

            var isValid = _certificateService.ValidateCertificate(clientCert);

            var result = new
            {
                IsValid = isValid,
                Certificate = new
                {
                    Subject = clientCert.Subject,
                    Issuer = clientCert.Issuer,
                    Thumbprint = clientCert.Thumbprint,
                    NotBefore = clientCert.NotBefore,
                    NotAfter = clientCert.NotAfter,
                    HasPrivateKey = clientCert.HasPrivateKey
                },
                ValidationTime = DateTime.UtcNow
            };

            _logger.LogInformation("Certificate validation result: {IsValid} for {Subject}",
                isValid, clientCert.Subject);

            return Ok(result);
        }

        [HttpPost("documents/sign")]
        [Authorize(Policy = "RequireDocumentSign")]
        public IActionResult SignDocument([FromBody] SignDocumentRequest request)
        {
            try
            {
                var docCertPath = _configuration["CertificateSettings:DocumentCertificate:Path"];
                var docCertPassword = _configuration["CertificateSettings:DocumentCertificate:Password"];

                using var cert = new X509Certificate2(docCertPath!, docCertPassword!);
                using var rsa = cert.GetRSAPrivateKey();

                if (rsa == null)
                    return BadRequest(new { message = "Certificate does not have private key for signing" });

                var dataBytes = Encoding.UTF8.GetBytes(request.Content);
                var hash = SHA256.HashData(dataBytes);
                var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                var user = User.Identity!.Name;
                _logger.LogInformation("Document signed by {User} using certificate {Subject}",
                    user, cert.Subject);

                return Ok(new
                {
                    OriginalContent = request.Content,
                    ContentHash = Convert.ToBase64String(hash),
                    Signature = Convert.ToBase64String(signature),
                    Certificate = cert.Subject,
                    CertificateThumbprint = cert.Thumbprint,
                    SignedAt = DateTime.UtcNow,
                    SignatureAlgorithm = "SHA256withRSA",
                    Verified = VerifySignature(dataBytes, signature, cert)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Document signing failed");
                return BadRequest(new { message = $"Document signing failed: {ex.Message}" });
            }
        }

        [HttpPost("code/sign")]
        [Authorize(Policy = "RequireCodeSign")]
        public IActionResult SignCode([FromBody] SignCodeRequest request)
        {
            try
            {
                var codeCertPath = _configuration["CertificateSettings:CodeCertificate:Path"];
                var codeCertPassword = _configuration["CertificateSettings:CodeCertificate:Password"];

                using var cert = new X509Certificate2(codeCertPath!, codeCertPassword!);
                using var rsa = cert.GetRSAPrivateKey();

                if (rsa == null)
                    return BadRequest(new { message = "Certificate does not have private key for signing" });

                var codeBytes = Encoding.UTF8.GetBytes(request.Code);
                var hash = SHA256.HashData(codeBytes);
                var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                var timestamp = DateTime.UtcNow;
                var timestampHash = SHA256.HashData(Encoding.UTF8.GetBytes(timestamp.ToString("O")));
                var timestampSignature = rsa.SignHash(timestampHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                var user = User.Identity!.Name;
                _logger.LogInformation("Code signed by {User} using certificate {Subject}",
                    user, cert.Subject);

                return Ok(new
                {
                    CodeHash = Convert.ToBase64String(hash),
                    Signature = Convert.ToBase64String(signature),
                    Timestamp = timestamp,
                    TimestampSignature = Convert.ToBase64String(timestampSignature),
                    Certificate = cert.Subject,
                    CertificateThumbprint = cert.Thumbprint,
                    SignedBy = user,
                    SignatureAlgorithm = "SHA256withRSA"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Code signing failed");
                return BadRequest(new { message = $"Code signing failed: {ex.Message}" });
            }
        }

        [HttpGet("test/mtls-simple")]
        [Authorize(AuthenticationSchemes = "Certificate")]
        public IActionResult TestMTLS()
        {
            var clientCert = HttpContext.Connection.ClientCertificate;

            return Ok(new
            {
                Message = "mTLS Authentication Successful!",
                AuthenticationMethod = "Client Certificate",
                Certificate = new
                {
                    Subject = clientCert!.Subject,
                    Issuer = clientCert.Issuer,
                    Thumbprint = clientCert.Thumbprint,
                    ValidFrom = clientCert.NotBefore,
                    ValidTo = clientCert.NotAfter
                },
                UserClaims = User.Claims.Select(c => new { c.Type, c.Value })
            });
        }

        private bool VerifySignature(byte[] data, byte[] signature, X509Certificate2 cert)
        {
            try
            {
                using var rsa = cert.GetRSAPublicKey();
                if (rsa == null) return false;

                var hash = SHA256.HashData(data);
                return rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch
            {
                return false;
            }
        }

        private List<string> GetEnhancedKeyUsages(X509Certificate2 cert)
        {
            var purposes = new List<string>();
            var enhancedKeyUsage = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();

            if (enhancedKeyUsage != null)
            {
                foreach (var oid in enhancedKeyUsage.EnhancedKeyUsages.OfType<Oid>())
                {
                    purposes.Add(oid.FriendlyName ?? oid.Value);
                }
            }

            return purposes;
        }

        private int? GetKeySize(X509Certificate2 cert)
        {
            try
            {
                using var rsa = cert.GetRSAPublicKey();
                if (rsa != null) return rsa.KeySize;

                using var ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa != null) return ecdsa.KeySize;
            }
            catch
            {
                // Ignore
            }
            return null;
        }
    }

    public class SignDocumentRequest
    {
        [Required]
        public string Content { get; set; } = string.Empty;
    }

    public class SignCodeRequest
    {
        [Required]
        public string Code { get; set; } = string.Empty;
    }
}
