namespace CertificatedDemo.Middleware
{
   

    public class CertificateLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<CertificateLoggingMiddleware> _logger;

        public CertificateLoggingMiddleware(
            RequestDelegate next,
            ILogger<CertificateLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var clientCert = context.Connection.ClientCertificate;

            if (clientCert != null)
            {
                _logger.LogInformation(
                    "Request from {RemoteIp} using certificate: {Subject} ({Thumbprint})",
                    context.Connection.RemoteIpAddress,
                    clientCert.Subject,
                    clientCert.Thumbprint);
            }

            await _next(context);
        }
    }
}
