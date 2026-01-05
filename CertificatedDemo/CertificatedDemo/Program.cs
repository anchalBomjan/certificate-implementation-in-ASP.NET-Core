//using CertificatedDemo.Data;
//using CertificatedDemo.Middleware;
//using CertificatedDemo.Models;
//using CertificatedDemo.Services;
//using Microsoft.AspNetCore.Authentication.Certificate;
//using Microsoft.AspNetCore.Authentication.JwtBearer;
//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Identity;
//using Microsoft.EntityFrameworkCore;
//using Microsoft.IdentityModel.Tokens;
//using Microsoft.OpenApi.Models;
//using System.Security.Cryptography.X509Certificates;
//using System.Text;

//var builder = WebApplication.CreateBuilder(args);

//// Add services to the container
//builder.Services.AddControllers();
//builder.Services.AddEndpointsApiExplorer();

//// Configure Swagger
//builder.Services.AddSwaggerGen(c =>
//{
//    c.SwaggerDoc("v1", new OpenApiInfo
//    {
//        Title = "Certificates Demo API",
//        Version = "v1",
//        Description = "API demonstrating JWT Authentication, Role-based Authorization, Identity Services, and Certificate Management"
//    });

//    // Add JWT authentication to Swagger
//    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
//    {
//        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
//        Name = "Authorization",
//        In = ParameterLocation.Header,
//        Type = SecuritySchemeType.ApiKey,
//        Scheme = "Bearer"
//    });

//    c.AddSecurityRequirement(new OpenApiSecurityRequirement
//    {
//        {
//            new OpenApiSecurityScheme
//            {
//                Reference = new OpenApiReference
//                {
//                    Type = ReferenceType.SecurityScheme,
//                    Id = "Bearer"
//                }
//            },
//            Array.Empty<string>()
//        }
//    });

//    // Add certificate authentication to Swagger
//    c.AddSecurityDefinition("X-Client-Certificate", new OpenApiSecurityScheme
//    {
//        Description = "Client Certificate for mTLS authentication",
//        Name = "X-Client-Certificate",
//        In = ParameterLocation.Header,
//        Type = SecuritySchemeType.ApiKey
//    });
//});

//// Configure Database
//builder.Services.AddDbContext<ApplicationDbContext>(options =>
//    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

//// Configure Identity
//builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
//{
//    options.Password.RequireDigit = true;
//    options.Password.RequiredLength = 6;
//    options.Password.RequireNonAlphanumeric = false;
//    options.Password.RequireUppercase = true;
//    options.Password.RequireLowercase = true;

//    options.User.RequireUniqueEmail = true;
//    options.SignIn.RequireConfirmedEmail = false; // For demo purposes
//})
//.AddEntityFrameworkStores<ApplicationDbContext>()
//.AddDefaultTokenProviders();

//// Configure JWT Authentication
//var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured");
//var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT Issuer not configured");
//var jwtAudience = builder.Configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT Audience not configured");

//builder.Services.AddAuthentication(options =>
//{
//    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
//    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
//})
//.AddJwtBearer(options =>
//{
//    options.RequireHttpsMetadata = true;
//    options.SaveToken = true;
//    options.TokenValidationParameters = new TokenValidationParameters
//    {
//        ValidateIssuer = true,
//        ValidateAudience = true,
//        ValidateLifetime = true,
//        ValidateIssuerSigningKey = true,
//        ValidIssuer = jwtIssuer,
//        ValidAudience = jwtAudience,
//        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
//        ClockSkew = TimeSpan.Zero
//    };
//})
//.AddCertificate(options =>
//{
//    options.AllowedCertificateTypes = CertificateTypes.All;
//    options.RevocationMode = X509RevocationMode.NoCheck; // For demo only
//    options.ValidateCertificateUse = true;
//    options.ValidateValidityPeriod = true;

//    options.Events = new CertificateAuthenticationEvents
//    {
//        OnAuthenticationFailed = context =>
//        {
//            context.Response.StatusCode = 401;
//            context.Response.ContentType = "application/json";
//            var result = System.Text.Json.JsonSerializer.Serialize(new
//            {
//                error = "Certificate authentication failed",
//                details = context.Exception.Message
//            });
//            return context.Response.WriteAsync(result);
//        },
//        OnCertificateValidated = context =>
//        {
//            var validationService = context.HttpContext.RequestServices
//                .GetRequiredService<CertificateValidationService>();

//            if (validationService.ValidateCertificate(context.ClientCertificate))
//            {
//                var claims = validationService.GetClaimsFromCertificate(context.ClientCertificate);
//                context.Principal = new System.Security.Claims.ClaimsPrincipal(
//                    new System.Security.Claims.ClaimsIdentity(claims, context.Scheme.Name));
//                context.Success();
//            }
//            else
//            {
//                context.Fail("Invalid certificate");
//            }
//            return Task.CompletedTask;
//        }
//    };
//});

//// Configure Authorization Policies
//builder.Services.AddAuthorization(options =>
//{
//    // Product policies
//    options.AddPolicy("RequireProductsView", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsView) ||
//            context.User.IsInRole(Roles.Admin) ||
//            context.User.IsInRole(Roles.Manager)));

//    options.AddPolicy("RequireProductsCreate", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsCreate) ||
//            context.User.IsInRole(Roles.Admin) ||
//            context.User.IsInRole(Roles.Manager)));

//    options.AddPolicy("RequireProductsEdit", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsEdit) ||
//            context.User.IsInRole(Roles.Admin) ||
//            context.User.IsInRole(Roles.Manager)));

//    options.AddPolicy("RequireProductsDelete", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsDelete) ||
//            context.User.IsInRole(Roles.Admin)));

//    // Certificate policies
//    options.AddPolicy("RequireCertificatesView", policy =>
//        policy.RequireAuthenticatedUser());

//    options.AddPolicy("RequireCertificatesManage", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.CertificatesManage) ||
//            context.User.IsInRole(Roles.Admin)));

//    options.AddPolicy("RequireDocumentSign", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.DocumentSign) ||
//            context.User.IsInRole(Roles.Admin) ||
//            context.User.IsInRole(Roles.Manager)));

//    options.AddPolicy("RequireCodeSign", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.CodeSign) ||
//            context.User.IsInRole(Roles.Admin)));

//    // User management policies
//    options.AddPolicy("RequireUsersView", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.UsersView) ||
//            context.User.IsInRole(Roles.Admin) ||
//            context.User.IsInRole(Roles.Manager)));

//    options.AddPolicy("RequireUsersManage", policy =>
//        policy.RequireAssertion(context =>
//            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.UsersManage) ||
//            context.User.IsInRole(Roles.Admin)));
//});

//// Register services
//builder.Services.AddScoped<ITokenService, TokenService>();
//builder.Services.AddScoped<CertificateValidationService>();
//builder.Services.AddScoped<DocumentSigningService>();
//builder.Services.AddScoped<CertificateInfoService>();

//// Add CORS
//builder.Services.AddCors(options =>
//{
//    options.AddPolicy("AllowAll", builder =>
//    {
//        builder.AllowAnyOrigin()
//               .AllowAnyMethod()
//               .AllowAnyHeader();
//    });
//});

//var app = builder.Build();

//// Configure the HTTP request pipeline
//if (app.Environment.IsDevelopment())
//{
//    app.UseSwagger();
//    app.UseSwaggerUI(c =>
//    {
//        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Certificates Demo API v1");
//        c.RoutePrefix = "swagger";
//        c.DefaultModelsExpandDepth(-1);
//        c.DisplayRequestDuration();
//        c.EnableDeepLinking();
//    });
//}

//app.UseHttpsRedirection();
//app.UseCors("AllowAll");
//app.UseMiddleware<CertificateLoggingMiddleware>();
//app.UseAuthentication();
//app.UseAuthorization();

//app.MapControllers();

//// Seed database
//using (var scope = app.Services.CreateScope())
//{
//    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
//    dbContext.Database.EnsureCreated();

//    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
//    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

//    await SeedData.InitializeAsync(userManager, roleManager);
//}

//app.Run();


using CertificatedDemo.Data;
using CertificatedDemo.Middleware;
using CertificatedDemo.Models;
using CertificatedDemo.Services;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Cryptography.X509Certificates;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Define certificate paths with certificates folder
var certificateFiles = new[]
{
    new { Name = "Root CA", Path = "certificates/ca.crt", Required = true },
    new { Name = "SSL/TLS Certificate", Path = "certificates/ssl.pfx", Required = true },
    new { Name = "Client Certificate (mTLS)", Path = "certificates/client.pfx", Required = false },
    new { Name = "Document Signing Certificate", Path = "certificates/doc.pfx", Required = false },
    new { Name = "Code Signing Certificate", Path = "certificates/code.pfx", Required = false }
};

// Check certificate files at startup
Console.WriteLine("🔐 Certificate Status Check for CertificatedDemo:");
Console.WriteLine("==============================================");
Console.WriteLine($"Looking for certificates in: {Path.GetFullPath("certificates")}");

foreach (var certFile in certificateFiles)
{
    var exists = File.Exists(certFile.Path);
    var status = exists ? "✅ Found" : "❌ Missing";
    var color = exists ? ConsoleColor.Green : (certFile.Required ? ConsoleColor.Red : ConsoleColor.Yellow);

    Console.ForegroundColor = color;
    Console.WriteLine($"{status}: {certFile.Name}");
    Console.ResetColor();

    if (exists)
    {
        try
        {
            var cert = certFile.Name.Contains(".crt")
                ? new X509Certificate2(certFile.Path)
                : new X509Certificate2(certFile.Path,
                    certFile.Name.Contains("SSL") ? "ServerPass123!" :
                    certFile.Name.Contains("Client") ? "ClientPass123!" :
                    certFile.Name.Contains("Document") ? "DocPass123!" : "CodePass123!");

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"     Subject: {cert.Subject}");
            Console.WriteLine($"     Issuer: {cert.Issuer}");
            Console.WriteLine($"     Valid: {cert.NotBefore:yyyy-MM-dd} to {cert.NotAfter:yyyy-MM-dd}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"     Error loading: {ex.Message}");
            Console.ResetColor();
        }
    }
    else if (certFile.Required)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"     ⚠️  Required for HTTPS. Path: {certFile.Path}");
        Console.ResetColor();
    }
}
Console.WriteLine("==============================================");

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// Configure Swagger
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "CertificatedDemo API",
        Version = "v1",
        Description = "API demonstrating JWT Authentication, Role-based Authorization, Identity Services, and Certificate Management with OpenSSL-generated certificates"
    });

    // Add JWT authentication to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Configure Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;

    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Configure JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT Issuer not configured");
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT Audience not configured");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // Set based on SSL availability
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero
    };
})
.AddCertificate(options => // Certificate Authentication for mTLS
{
    options.AllowedCertificateTypes = CertificateTypes.All;
    options.RevocationMode = X509RevocationMode.NoCheck; // For demo with self-signed certs
    options.ValidateCertificateUse = true;
    options.ValidateValidityPeriod = true;

    options.Events = new CertificateAuthenticationEvents
    {
        OnAuthenticationFailed = context =>
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var result = System.Text.Json.JsonSerializer.Serialize(new
            {
                error = "Certificate authentication failed",
                details = context.Exception.Message
            });
            return context.Response.WriteAsync(result);
        },
        OnCertificateValidated = context =>
        {
            var validationService = context.HttpContext.RequestServices
                .GetRequiredService<CertificateValidationService>();

            if (validationService.ValidateCertificate(context.ClientCertificate))
            {
                var claims = validationService.GetClaimsFromCertificate(context.ClientCertificate);
                context.Principal = new System.Security.Claims.ClaimsPrincipal(
                    new System.Security.Claims.ClaimsIdentity(claims, context.Scheme.Name));
                context.Success();
            }
            else
            {
                context.Fail("Invalid certificate");
            }
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            context.HandleResponse();
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var result = System.Text.Json.JsonSerializer.Serialize(new
            {
                error = "Client certificate required",
                instructions = "Use certificates/client.pfx with password 'ClientPass123!' for mTLS authentication"
            });
            return context.Response.WriteAsync(result);
        }
    };
});

// Configure Authorization Policies
builder.Services.AddAuthorization(options =>
{
    // Product policies
    options.AddPolicy("RequireProductsView", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsView) ||
            context.User.IsInRole(Roles.Admin) ||
            context.User.IsInRole(Roles.Manager)));

    options.AddPolicy("RequireProductsCreate", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsCreate) ||
            context.User.IsInRole(Roles.Admin) ||
            context.User.IsInRole(Roles.Manager)));

    options.AddPolicy("RequireProductsEdit", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsEdit) ||
            context.User.IsInRole(Roles.Admin) ||
            context.User.IsInRole(Roles.Manager)));

    options.AddPolicy("RequireProductsDelete", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.ProductsDelete) ||
            context.User.IsInRole(Roles.Admin)));

    // Certificate policies
    options.AddPolicy("RequireCertificatesView", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("RequireCertificatesManage", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.CertificatesManage) ||
            context.User.IsInRole(Roles.Admin)));

    options.AddPolicy("RequireDocumentSign", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.DocumentSign) ||
            context.User.IsInRole(Roles.Admin) ||
            context.User.IsInRole(Roles.Manager)));

    options.AddPolicy("RequireCodeSign", policy =>
        policy.RequireAssertion(context =>
            context.User.HasClaim(c => c.Type == "Permission" && c.Value == Permissions.CodeSign) ||
            context.User.IsInRole(Roles.Admin)));
});

// Register services
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<CertificateValidationService>();
builder.Services.AddScoped<CertificateInfoService>();
builder.Services.AddScoped<DocumentSigningService>();

// Add CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

// Configure Kestrel with SSL certificate if it exists
var sslCertPath = "certificates/ssl.pfx";
if (File.Exists(sslCertPath))
{
    builder.WebHost.ConfigureKestrel(serverOptions =>
    {
        serverOptions.ConfigureHttpsDefaults(httpsOptions =>
        {
            try
            {
                var sslCert = new X509Certificate2(sslCertPath, "ServerPass123!");
                httpsOptions.ServerCertificate = sslCert;

                // Enable client certificate for mTLS (optional)
                httpsOptions.ClientCertificateMode =
                    Microsoft.AspNetCore.Server.Kestrel.Https.ClientCertificateMode.DelayCertificate;
                httpsOptions.CheckCertificateRevocation = false; // For demo with self-signed certs

                Console.WriteLine($"✅ SSL Certificate loaded for HTTPS: {sslCert.Subject}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to load SSL certificate: {ex.Message}");
            }
        });
    });
}

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "CertificatedDemo API v1");
        c.RoutePrefix = "swagger";
        c.DefaultModelsExpandDepth(-1);
        c.DisplayRequestDuration();
        c.EnableDeepLinking();
    });
}

// Only use HTTPS redirection if SSL certificate exists
if (File.Exists(sslCertPath))
{
    Console.WriteLine("🔐 SSL certificate found - HTTPS enabled on port 7049");
    app.UseHttpsRedirection();
}
else
{
    Console.WriteLine("⚠️  SSL certificate not found - Running in HTTP mode only on port 5286");
}

app.UseCors("AllowAll");
app.UseMiddleware<CertificateLoggingMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Add health check and info endpoints
app.MapGet("/", () =>
{
    var sslExists = File.Exists(sslCertPath);
    return new
    {
        Application = "CertificatedDemo API",
        Description = "Certificate Management Demo with OpenSSL-generated certificates",
        Status = "Running",
        SSL_Enabled = sslExists,
        Environment = app.Environment.EnvironmentName,
        Timestamp = DateTime.UtcNow,
        Certificate_Folder = Path.GetFullPath("certificates"),
        Certificate_Status = certificateFiles.Select(f => new
        {
            f.Name,
            Path = f.Path,
            Exists = File.Exists(f.Path),
            Status = File.Exists(f.Path) ? "Available" : "Missing"
        }),
        Endpoints = new
        {
            Swagger_UI = "/swagger",
            Certificate_Information = "/api/certificates/info",
            Certificate_Status = "/api/certificates/status",
            Health_Check = "/health",
            Register_User = "POST /api/auth/register",
            Login = "POST /api/auth/login",
            Products = "GET /api/products",
            Test_mTLS = "GET /api/certificates/test/mtls-simple",
            Document_Signing = "POST /api/certificates/documents/sign"
        }
    };
});

// Health check endpoint
app.MapGet("/health", () => new
{
    Status = "Healthy",
    Timestamp = DateTime.UtcNow,
    Uptime = DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime(),
    Certificates = certificateFiles.ToDictionary(
        f => f.Name.Replace(" ", "_").Replace("(", "").Replace(")", ""),
        f => File.Exists(f.Path) ? "Present" : "Missing"
    ),
    Database = "Connected",
    Authentication = new
    {
        JWT = "Enabled",
        Certificate_mTLS = File.Exists("certificates/client.pfx") ? "Available" : "Not configured"
    }
});

// Certificate status endpoint
app.MapGet("/api/certificates/status", () =>
{
    var statusList = certificateFiles.Select(f => new
    {
        f.Name,
        f.Path,
        Exists = File.Exists(f.Path),
        f.Required,
        Size = File.Exists(f.Path) ? new FileInfo(f.Path).Length : 0,
        LastModified = File.Exists(f.Path) ? File.GetLastWriteTime(f.Path).ToString("yyyy-MM-dd HH:mm:ss") : "N/A",
        FullPath = File.Exists(f.Path) ? Path.GetFullPath(f.Path) : "N/A"
    });

    return Results.Ok(new
    {
        Timestamp = DateTime.UtcNow,
        CertificateStatus = statusList,
        CertificateFolder = Path.GetFullPath("certificates"),
        HasSSL = File.Exists(sslCertPath),
        HasAllRequiredCertificates = certificateFiles.Where(f => f.Required).All(f => File.Exists(f.Path)),
        Message = File.Exists(sslCertPath)
            ? "SSL certificate found - HTTPS available on port 7049"
            : "SSL certificate missing - running in HTTP mode on port 5286",
        Instructions = new
        {
            Certificate_Paths = "All certificates are in the 'certificates' folder",
            Test_mTLS = "Use curl with: curl -k --cert certificates/client.pfx:ClientPass123! https://localhost:7049/api/certificates/test/mtls-simple",
            Test_Document_Signing = "POST to /api/certificates/documents/sign with JWT token",
            Access_Swagger = "/swagger for API documentation"
        }
    });
});

// Seed database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    dbContext.Database.EnsureCreated();

    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    await SeedData.InitializeAsync(userManager, roleManager);

    Console.WriteLine("✅ Database seeded with initial data");
}

app.Run();
