using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace CustomAuthorizationServerOAuthProvider.Provider
{
    public class AuthorizationServerApplyRedirectContext : BaseContext<AuthorizationServerAuthenticationOptions>
    {
        public AuthorizationServerApplyRedirectContext(
            IOwinContext context,
            AuthorizationServerAuthenticationOptions options,
            AuthenticationProperties properties,
            string redirectUri) : base(context, options)
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

        public string RedirectUri { get; private set; }

        public AuthenticationProperties Properties { get; private set; }
    }
}
