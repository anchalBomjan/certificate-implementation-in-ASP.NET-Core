using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
namespace CertificateDemoAPI.Utils
{
    public static class CertificateGenerator
    {
        public static void GenerateTestCertificates(string outputPath)
        {
            Console.WriteLine("Generating test certificates...");

            // Create directory if it doesn't exist
            Directory.CreateDirectory(outputPath);

            // 1. Root CA
            Console.WriteLine("Creating Root CA certificate...");
            var rootCa = CreateCertificateAuthority(
                "CN=Certificate Demo Root CA, O=Demo Corp, C=US",
                5
            );

            // 2. Intermediate CA
            Console.WriteLine("Creating Intermediate CA certificate...");
            var intermediateCa = CreateIntermediateCA(
                "CN=Certificate Demo Intermediate CA, O=Demo Corp, C=US",
                rootCa,
                3
            );

            // 3. Server certificate
            Console.WriteLine("Creating Server certificate...");
            var serverCert = CreateServerCertificate(
                "CN=localhost",
                intermediateCa,
                2,
                new[] { "localhost", "127.0.0.1", "::1" }
            );

            // 4. Client signing certificate
            Console.WriteLine("Creating Client Signing certificate...");
            var clientSigningCert = CreateClientCertificate(
                "CN=Demo Signing User",
                intermediateCa,
                2,
                false
            );

            // 5. Client authentication certificate
            Console.WriteLine("Creating Client Authentication certificate...");
            var clientAuthCert = CreateClientCertificate(
                "CN=Demo API Client",
                intermediateCa,
                2,
                true
            );

            // Export all certificates
            ExportCertificates(outputPath, rootCa, intermediateCa, serverCert, clientSigningCert, clientAuthCert);

            Console.WriteLine("Certificates generated successfully!");
            Console.WriteLine($"Location: {outputPath}");
        }

        //private static X509Certificate2 CreateCertificateAuthority(string subjectName, int yearsValid)
        //{
        //    using var rsa = RSA.Create(4096);
        //    var request = new CertificateRequest(
        //        subjectName,
        //        rsa,
        //        HashAlgorithmName.SHA256,
        //        RSASignaturePadding.Pkcs1);

        //    request.CertificateExtensions.Add(
        //        new X509BasicConstraintsExtension(true, true, 1, true));

        //    request.CertificateExtensions.Add(
        //        new X509KeyUsageExtension(
        //            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
        //            true));

        //    var subjectKeyId = CreateSubjectKeyIdentifier(rsa);
        //    request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(subjectKeyId, false));

        //    var rootCert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(yearsValid));
        //    return rootCert;
        //}

        private static X509Certificate2 CreateCertificateAuthority(string subjectName, int yearsValid)
        {
            using var rsa = RSA.Create(4096);

            var request = new CertificateRequest(
                subjectName,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, true, 1, true));

            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                    true));

            var subjectKeyId = CreateSubjectKeyIdentifier(rsa);
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(subjectKeyId, false));

            var rootCert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
                                                     DateTimeOffset.UtcNow.AddYears(yearsValid));

            // Export & re-import to make private key exportable
            return new X509Certificate2(
                rootCert.Export(X509ContentType.Pfx, "password123"),
                "password123",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
            );
        }


        private static X509Certificate2 CreateIntermediateCA(string subjectName, X509Certificate2 rootCa, int yearsValid)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection(), false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(CreateSubjectKeyIdentifier(rsa), false));

            using var issuerKey = rootCa.GetRSAPrivateKey();
            if (issuerKey == null)
                throw new InvalidOperationException("Root CA certificate doesn't have private key");

            var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
            var serialNumber = GenerateSerialNumber();

            var signedCert = request.Create(rootCa.SubjectName, generator, DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(yearsValid), serialNumber);

            return new X509Certificate2(
                signedCert.Export(X509ContentType.Pfx, "password123"),
                "password123",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }

        private static X509Certificate2 CreateServerCertificate(string commonName, X509Certificate2 issuer, int yearsValid, string[] dnsNames)
        {
            using var rsa = RSA.Create(2048);
            var subjectName = $"CN={commonName}, O=Demo Corp, C=US";

            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var dns in dnsNames)
                sanBuilder.AddDnsName(dns);
            request.CertificateExtensions.Add(sanBuilder.Build());

            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(CreateSubjectKeyIdentifier(rsa), false));

            using var issuerKey = issuer.GetRSAPrivateKey();
            var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
            var serialNumber = GenerateSerialNumber();

            var signedCert = request.Create(issuer.SubjectName, generator, DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(yearsValid), serialNumber);

            return new X509Certificate2(
                signedCert.Export(X509ContentType.Pfx, "password123"),
                "password123",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }

        private static X509Certificate2 CreateClientCertificate(string commonName, X509Certificate2 issuer, int yearsValid, bool isForAuthentication)
        {
            using var rsa = RSA.Create(2048);
            var subjectName = $"CN={commonName}, O=Demo Corp, C=US";

            var request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation, true));

            var ekuOids = new OidCollection();
            if (isForAuthentication)
                ekuOids.Add(new Oid("1.3.6.1.5.5.7.3.2")); // Client Authentication
            else
            {
                ekuOids.Add(new Oid("1.3.6.1.5.5.7.3.4")); // Email Protection
                ekuOids.Add(new Oid("1.3.6.1.5.5.7.3.3")); // Code Signing
            }

            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekuOids, false));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(CreateSubjectKeyIdentifier(rsa), false));

            using var issuerKey = issuer.GetRSAPrivateKey();
            var generator = X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
            var serialNumber = GenerateSerialNumber();

            var signedCert = request.Create(issuer.SubjectName, generator, DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(yearsValid), serialNumber);

            return new X509Certificate2(
                signedCert.Export(X509ContentType.Pfx, "password123"),
                "password123",
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        }

        private static byte[] CreateSubjectKeyIdentifier(RSA rsa)
        {
            var parameters = rsa.ExportParameters(false);
            var hash = SHA256.HashData(parameters.Modulus);
            var ski = new byte[20];
            Array.Copy(hash, hash.Length - 20, ski, 0, 20);
            return ski;
        }

        private static byte[] GenerateSerialNumber()
        {
            var serialNumber = new byte[16];
            RandomNumberGenerator.Fill(serialNumber);
            return serialNumber;
        }

        private static void ExportCertificates(string outputPath, params X509Certificate2[] certificates)
        {
            var names = new[] { "root-ca", "intermediate-ca", "server", "client-signing", "client-auth" };

            for (int i = 0; i < certificates.Length; i++)
            {
                var cert = certificates[i];
                var name = names[i];

                // Export PFX
                if (cert.HasPrivateKey)
                {
                    File.WriteAllBytes(Path.Combine(outputPath, $"{name}.pfx"), cert.Export(X509ContentType.Pfx, "password123"));
                    Console.WriteLine($"Created: {name}.pfx");
                }

                // Export CER
                File.WriteAllBytes(Path.Combine(outputPath, $"{name}.cer"), cert.Export(X509ContentType.Cert));
                Console.WriteLine($"Created: {name}.cer");

                // Export PEM
                var pem = new StringBuilder();
                pem.AppendLine("-----BEGIN CERTIFICATE-----");
                pem.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                pem.AppendLine("-----END CERTIFICATE-----");
                File.WriteAllText(Path.Combine(outputPath, $"{name}.pem"), pem.ToString());
                Console.WriteLine($"Created: {name}.pem");

                // Export CA private key as PEM
                if ((name == "root-ca" || name == "intermediate-ca") && cert.HasPrivateKey)
                {
                    var privateKeyPem = ExportPrivateKeyAsPem(cert);
                    File.WriteAllText(Path.Combine(outputPath, $"{name}-key.pem"), privateKeyPem);
                    Console.WriteLine($"Created: {name}-key.pem");
                }
            }

            // Create bundle.pem
            var bundle = new StringBuilder();
            foreach (var cert in certificates)
            {
                bundle.AppendLine($"# Subject: {cert.Subject}");
                bundle.AppendLine($"# Issuer: {cert.Issuer}");
                bundle.AppendLine($"# Thumbprint: {cert.Thumbprint}");
                bundle.AppendLine($"# Valid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}");
                bundle.AppendLine("-----BEGIN CERTIFICATE-----");
                bundle.AppendLine(Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks));
                bundle.AppendLine("-----END CERTIFICATE-----");
                bundle.AppendLine();
            }
            File.WriteAllText(Path.Combine(outputPath, "bundle.pem"), bundle.ToString());
            Console.WriteLine("Created: bundle.pem");
        }

        private static string ExportPrivateKeyAsPem(X509Certificate2 cert)
        {
            using var rsa = cert.GetRSAPrivateKey();
            var privateKeyBytes = rsa.ExportPkcs8PrivateKey();
            var base64 = Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks);

            var pem = new StringBuilder();
            pem.AppendLine("-----BEGIN PRIVATE KEY-----");
            pem.AppendLine(base64);
            pem.AppendLine("-----END PRIVATE KEY-----");
            return pem.ToString();
        }
    }
}
