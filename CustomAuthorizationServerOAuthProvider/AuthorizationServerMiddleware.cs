using System;
using System.Net.Http;
using CustomAuthorizationServerOAuthProvider.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace CustomAuthorizationServerOAuthProvider
{
    public class AuthorizationServerMiddleware : AuthenticationMiddleware<AuthorizationServerAuthenticationOptions>
    {
        readonly HttpClient _httpClient;
        readonly ILogger _logger;

        public AuthorizationServerMiddleware(
            OwinMiddleware next, IAppBuilder app,
            AuthorizationServerAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException("ClientId must be provided");
            }
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException("ClientSecret must be provided");
            }

            _logger = app.CreateLogger<AuthorizationServerMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new AuthorizationServerAuthenticationProvider();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10MB
            };
        }

        protected override AuthenticationHandler<AuthorizationServerAuthenticationOptions> CreateHandler()
            => new AuthorizationServerAuthenticationHandler(_httpClient, _logger);

        private HttpMessageHandler ResolveHttpMessageHandler(
            AuthorizationServerAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Vaidator Handler Mismatch");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}