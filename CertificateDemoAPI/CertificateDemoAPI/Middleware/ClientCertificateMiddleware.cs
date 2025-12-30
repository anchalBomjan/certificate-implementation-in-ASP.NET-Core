namespace CertificateDemoAPI.Middleware
{


    public class ClientCertificateMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ClientCertificateMiddleware> _logger;

        public ClientCertificateMiddleware(
            RequestDelegate next,
            ILogger<ClientCertificateMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var clientCertificate = context.Connection.ClientCertificate;

            if (clientCertificate != null)
            {
                _logger.LogInformation("Client certificate detected: {Subject} ({Thumbprint})",
                    clientCertificate.Subject, clientCertificate.Thumbprint);

                // Add certificate info to response headers for debugging
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers.Append("X-Client-Certificate-Subject",
                        clientCertificate.Subject);
                    context.Response.Headers.Append("X-Client-Certificate-Thumbprint",
                        clientCertificate.Thumbprint);
                    context.Response.Headers.Append("X-Client-Certificate-Valid-From",
                        clientCertificate.NotBefore.ToString("O"));
                    context.Response.Headers.Append("X-Client-Certificate-Valid-To",
                        clientCertificate.NotAfter.ToString("O"));

                    return Task.CompletedTask;
                });
            }
            else
            {
                _logger.LogDebug("No client certificate provided for request to {Path}",
                    context.Request.Path);
            }

            await _next(context);
        }
    }

    // Extension method for registering middleware
    public static class ClientCertificateMiddlewareExtensions
    {
        public static IApplicationBuilder UseClientCertificateLogging(
            this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ClientCertificateMiddleware>();
        }
    }
}
