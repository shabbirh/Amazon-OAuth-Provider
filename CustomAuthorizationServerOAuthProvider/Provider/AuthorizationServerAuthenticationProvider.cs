using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomAuthorizationServerOAuthProvider.Provider
{
    public class AuthorizationServerAuthenticationProvider : IAuthorizationServerAuthenticationProvider
    {

        public AuthorizationServerAuthenticationProvider()
        {

        }

        public Func<AuthorizationServerAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<AuthorizationServerEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Action<AuthorizationServerApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(
            AuthorizationServerAuthenticatedContext context) => OnAuthenticated(context);

        public Task ReturnEndpoint(
            AuthorizationServerEndpointContext context) => OnReturnEndpoint(context);

        public void ApplyRedirect(
            AuthorizationServerApplyRedirectContext context) => OnApplyRedirect(context);

    }
}
