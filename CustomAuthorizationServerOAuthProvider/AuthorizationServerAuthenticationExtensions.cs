using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Owin;

namespace CustomAuthorizationServerOAuthProvider
{
    public static class AuthorizationServerAuthenticationExtensions
    {
        public static IAppBuilder UseAuthorizationServerAuthentication(this IAppBuilder app, AuthorizationServerAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));

            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(AuthorizationServerMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseAuthorizationServerAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret) => app.UseAuthorizationServerAuthentication(
            new AuthorizationServerAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
    }
}
