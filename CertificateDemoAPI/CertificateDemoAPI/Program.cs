using CertificateDemoAPI.Middleware;
using CertificateDemoAPI.Services;
using CertificateDemoAPI.Utils;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Certificate Demo API",
        Version = "v1",
        Description = "API demonstrating SSL/TLS, Client Certificates and Document Signing"
    });

    // Add security definition for client certificate
    c.AddSecurityDefinition("ClientCertificate", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
        Name = "X-Client-Certificate",
        Description = "Client certificate thumbprint"
    });

    // Make sure all endpoints requiring auth show the security requirement
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "ClientCertificate"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Register custom services
builder.Services.AddSingleton<ICertificateValidationService, CertificateValidationService>();
builder.Services.AddSingleton<IDigitalSignatureService, DigitalSignatureService>();

// Configure client certificate authentication
builder.Services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.RevocationMode = X509RevocationMode.NoCheck; // For demo only

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var validationService = context.HttpContext.RequestServices
                    .GetRequiredService<ICertificateValidationService>();

                if (validationService.ValidateCertificate(context.ClientCertificate))
                {
                    var claims = new[]
                    {
                        new Claim(ClaimTypes.Name,
                            context.ClientCertificate.Subject,
                            ClaimValueTypes.String),
                        new Claim(ClaimTypes.NameIdentifier,
                            context.ClientCertificate.Thumbprint),
                        new Claim("Certificate.Issuer",
                            context.ClientCertificate.Issuer),
                        new Claim("Certificate.ValidFrom",
                            context.ClientCertificate.NotBefore.ToString()),
                        new Claim("Certificate.ValidTo",
                            context.ClientCertificate.NotAfter.ToString())
                    };

                    var identity = new ClaimsIdentity(claims, context.Scheme.Name);
                    context.Principal = new ClaimsPrincipal(identity);
                    context.Success();
                }
                else
                {
                    context.Fail("Invalid certificate");
                }

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                context.Fail("Certificate authentication failed");
                return Task.CompletedTask;
            }
        };
    });

// Configure Kestrel for HTTPS with certificate
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    // Get certificate path from configuration or use default
    var certPath = builder.Configuration["Kestrel:Certificates:Default:Path"]
        ?? "certs/server.pfx";
    var certPassword = builder.Configuration["Kestrel:Certificates:Default:Password"]
        ?? "password123";

    if (File.Exists(certPath))
    {
        serverOptions.ConfigureHttpsDefaults(httpsOptions =>
        {
            httpsOptions.ServerCertificate = new X509Certificate2(certPath, certPassword);
            httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            httpsOptions.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        });
    }

    serverOptions.ConfigureEndpointDefaults(listenOptions =>
    {
        listenOptions.UseHttps();
    });
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireClientCertificate", policy =>
        policy.RequireAuthenticatedUser());
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Certificate Demo API v1");
        c.RoutePrefix = "swagger";
    });
}

// Add custom middleware for logging client certificate info
app.UseMiddleware<ClientCertificateMiddleware>();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Generate test certificates if they don't exist
var certsDir = Path.Combine(Directory.GetCurrentDirectory(), "certs");
if (!Directory.Exists(certsDir) || !Directory.GetFiles(certsDir).Any())
{
    Directory.CreateDirectory(certsDir);
    CertificateGenerator.GenerateTestCertificates(certsDir);

    Console.WriteLine($"Test certificates generated in: {certsDir}");
    Console.WriteLine("CA Certificate: certs/ca.cer");
    Console.WriteLine("Server Certificate: certs/server.pfx (password: password123)");
    Console.WriteLine("Client Certificate: certs/client.pfx (password: password123)");
}

app.Run();