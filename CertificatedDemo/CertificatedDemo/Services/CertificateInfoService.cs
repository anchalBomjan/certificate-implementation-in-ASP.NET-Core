using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertificatedDemo.Services;

public class CertificateInfoService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<CertificateInfoService> _logger;

    public CertificateInfoService(IConfiguration configuration, ILogger<CertificateInfoService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public async Task LogCertificateInfo(HttpContext context)
    {
        try
        {
            var clientCert = context.Connection.ClientCertificate;

            if (clientCert != null)
            {
                _logger.LogInformation(
                    "🔐 Certificate Request - IP: {IP}, Subject: {Subject}, Thumbprint: {Thumbprint}",
                    context.Connection.RemoteIpAddress,
                    clientCert.Subject,
                    clientCert.Thumbprint);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error logging certificate information");
        }

        await Task.CompletedTask;
    }

    public Dictionary<string, object> GetAllCertificateInfo()
    {
        var certificates = new Dictionary<string, object>();

        // Define certificate files with certificates folder
        var certFiles = new[]
        {
            new { Name = "Root CA", Path = "certificates/ca.crt", Password = (string?)null },
            new { Name = "SSL/TLS Server", Path = "certificates/ssl.pfx", Password = "ServerPass123!" },
            new { Name = "Client mTLS", Path = "certificates/client.pfx", Password = "ClientPass123!" },
            new { Name = "Document Signing", Path = "certificates/doc.pfx", Password = "DocPass123!" },
            new { Name = "Code Signing", Path = "certificates/code.pfx", Password = "CodePass123!" }
        };

        foreach (var certFile in certFiles)
        {
            try
            {
                if (File.Exists(certFile.Path))
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
                        ValidFrom = cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss"),
                        ValidTo = cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"),
                        HasPrivateKey = cert.HasPrivateKey,
                        KeyAlgorithm = cert.GetKeyAlgorithm(),
                        KeySize = GetKeySize(cert),
                        Purposes = GetCertificatePurposes(cert),
                        IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter,
                        FilePath = Path.GetFullPath(certFile.Path)
                    };
                }
                else
                {
                    certificates[certFile.Name] = new
                    {
                        Error = $"File not found: {certFile.Path}",
                        FullPath = Path.GetFullPath(certFile.Path)
                    };
                }
            }
            catch (Exception ex)
            {
                certificates[certFile.Name] = new
                {
                    Error = ex.Message,
                    FilePath = Path.GetFullPath(certFile.Path)
                };
            }
        }

        return certificates;
    }

    public object GetCertificateDetails(string certificateType)
    {
        return certificateType.ToLower() switch
        {
            "ssl" or "tls" => GetCertificateInfo("certificates/ssl.pfx", "ServerPass123!"),
            "client" or "mtls" => GetCertificateInfo("certificates/client.pfx", "ClientPass123!"),
            "document" or "doc" => GetCertificateInfo("certificates/doc.pfx", "DocPass123!"),
            "code" => GetCertificateInfo("certificates/code.pfx", "CodePass123!"),
            "root" or "ca" => GetCertificateInfo("certificates/ca.crt", null),
            _ => new { Error = $"Unknown certificate type: {certificateType}" }
        };
    }

    private object GetCertificateInfo(string path, string? password)
    {
        try
        {
            if (!File.Exists(path))
                return new { Error = $"File not found: {path}", FullPath = Path.GetFullPath(path) };

            var cert = password == null
                ? new X509Certificate2(path)
                : new X509Certificate2(path, password);

            return new
            {
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                SerialNumber = cert.SerialNumber,
                ValidFrom = cert.NotBefore,
                ValidTo = cert.NotAfter,
                HasPrivateKey = cert.HasPrivateKey,
                KeyAlgorithm = cert.GetKeyAlgorithm(),
                KeySize = GetKeySize(cert),
                Purposes = GetCertificatePurposes(cert),
                SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName,
                Version = cert.Version,
                IsValid = DateTime.Now >= cert.NotBefore && DateTime.Now <= cert.NotAfter,
                DaysRemaining = (cert.NotAfter - DateTime.Now).Days,
                FilePath = Path.GetFullPath(path)
            };
        }
        catch (Exception ex)
        {
            return new { Error = ex.Message, FilePath = Path.GetFullPath(path) };
        }
    }

    private List<string> GetCertificatePurposes(X509Certificate2 cert)
    {
        var purposes = new List<string>();

        var enhancedKeyUsage = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (enhancedKeyUsage != null)
        {
            foreach (var oid in enhancedKeyUsage.EnhancedKeyUsages.OfType<Oid>())
            {
                var purpose = oid.FriendlyName ?? oid.Value switch
                {
                    "1.3.6.1.5.5.7.3.1" => "Server Authentication",
                    "1.3.6.1.5.5.7.3.2" => "Client Authentication",
                    "1.3.6.1.5.5.7.3.3" => "Code Signing",
                    "1.3.6.1.5.5.7.3.4" => "Email Protection",
                    "1.3.6.1.5.5.7.3.8" => "Time Stamping",
                    _ => oid.Value
                };
                purposes.Add(purpose);
            }
        }

        return purposes;
    }

    private int? GetKeySize(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null)
                return rsa.KeySize;

            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null)
                return ecdsa.KeySize;
        }
        catch
        {
            // Ignore errors
        }
        return null;
    }
}