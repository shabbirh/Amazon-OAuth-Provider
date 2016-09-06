using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace CustomAuthorizationServerOAuthProvider.Provider
{
    public class AuthorizationServerEndpointContext : ReturnEndpointContext
    {
        public AuthorizationServerEndpointContext(
            IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}