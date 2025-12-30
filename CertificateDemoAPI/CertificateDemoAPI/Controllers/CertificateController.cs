using CertificateDemoAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificateDemoAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class CertificateController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public CertificateController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("server-info")]
        [AllowAnonymous]
        public IActionResult GetServerCertificateInfo()
        {
            try
            {
                var connection = HttpContext.Connection;
                var serverCertificate = connection.ClientCertificate; // Note: This might be null

                // Get server certificate from Kestrel configuration
                //var certPath = _configuration["Kestrel:Certificates:Default:Path"];
                var certPath = _configuration["Kestrel:Endpoints:Https:Certificate:Path"];
                var certPassword = _configuration["Kestrel:Endpoints:Https:Certificate:Password"];

                //var certPassword = _configuration["Kestrel:Certificates:Default:Password"];

                if (!string.IsNullOrEmpty(certPath) && System.IO. File.Exists(certPath))
                {
                    var certificate = new X509Certificate2(certPath, certPassword);

                    var info = new CertificateInfo
                    {
                        Subject = certificate.Subject,
                        Issuer = certificate.Issuer,
                        Thumbprint = certificate.Thumbprint,
                        ValidFrom = certificate.NotBefore,
                        ValidTo = certificate.NotAfter,
                        HasPrivateKey = certificate.HasPrivateKey,
                        KeyUsages = GetKeyUsages(certificate),
                        EnhancedKeyUsages = GetEnhancedKeyUsages(certificate)
                    };

                    return Ok(new
                    {
                        Success = true,
                        Certificate = info,
                        Message = "Server certificate information"
                    });
                }

                return Ok(new
                {
                    Success = false,
                    Message = "Server certificate not configured"
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Success = false,
                    Error = ex.Message
                });
            }
        }

        [HttpGet("client-info")]
        [Authorize(AuthenticationSchemes = "Certificate")]
        public IActionResult GetClientCertificateInfo()
        {
            var clientCert = HttpContext.Connection.ClientCertificate;

            if (clientCert == null)
            {
                return Unauthorized(new { Message = "Client certificate not provided" });
            }

            var info = new CertificateInfo
            {
                Subject = clientCert.Subject,
                Issuer = clientCert.Issuer,
                Thumbprint = clientCert.Thumbprint,
                ValidFrom = clientCert.NotBefore,
                ValidTo = clientCert.NotAfter,
                HasPrivateKey = clientCert.HasPrivateKey,
                KeyUsages = GetKeyUsages(clientCert),
                EnhancedKeyUsages = GetEnhancedKeyUsages(clientCert)
            };

            return Ok(new
            {
                Success = true,
                Certificate = info,
                User = User.Identity?.Name,
                Claims = User.Claims.Select(c => new { c.Type, c.Value })
            });
        }

        [HttpGet("test-connection")]
        [AllowAnonymous]
        public IActionResult TestConnection()
        {
            var isHttps = Request.IsHttps;
            var protocol = Request.Protocol;
            var hasClientCert = HttpContext.Connection.ClientCertificate != null;

            return Ok(new
            {
                Message = "Certificate Demo API is running",
                IsHttps = isHttps,
                Protocol = protocol,
                HasClientCertificate = hasClientCert,
                ServerTime = DateTime.UtcNow,
                Headers = Request.Headers
                    .Where(h => h.Key.StartsWith("X-") || h.Key == "Authorization")
                    .ToDictionary(h => h.Key, h => h.Value.ToString())
            });
        }

        private List<string> GetKeyUsages(X509Certificate2 certificate)
        {
            var usages = new List<string>();
            var keyUsageExtensions = certificate.Extensions.OfType<X509KeyUsageExtension>();

            if (keyUsageExtensions.Any())
            {
                var keyUsage = keyUsageExtensions.First();
                var flags = keyUsage.KeyUsages;

                if (flags.HasFlag(X509KeyUsageFlags.DigitalSignature))
                    usages.Add("DigitalSignature");
                if (flags.HasFlag(X509KeyUsageFlags.NonRepudiation))
                    usages.Add("NonRepudiation");
                if (flags.HasFlag(X509KeyUsageFlags.KeyEncipherment))
                    usages.Add("KeyEncipherment");
                if (flags.HasFlag(X509KeyUsageFlags.DataEncipherment))
                    usages.Add("DataEncipherment");
                if (flags.HasFlag(X509KeyUsageFlags.KeyAgreement))
                    usages.Add("KeyAgreement");
                if (flags.HasFlag(X509KeyUsageFlags.KeyCertSign))
                    usages.Add("KeyCertSign");
                if (flags.HasFlag(X509KeyUsageFlags.CrlSign))
                    usages.Add("CrlSign");
                if (flags.HasFlag(X509KeyUsageFlags.EncipherOnly))
                    usages.Add("EncipherOnly");
                if (flags.HasFlag(X509KeyUsageFlags.DecipherOnly))
                    usages.Add("DecipherOnly");
            }

            return usages;
        }

        private List<string> GetEnhancedKeyUsages(X509Certificate2 certificate)
        {
            var ekuList = new List<string>();
            var ekuExtensions = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>();

            if (ekuExtensions.Any())
            {
                var eku = ekuExtensions.First();
                foreach (var oid in eku.EnhancedKeyUsages.Cast<Oid>())
                {
                    ekuList.Add(oid.FriendlyName ?? oid.Value);
                }
            }

            return ekuList;
        }
    }
}
