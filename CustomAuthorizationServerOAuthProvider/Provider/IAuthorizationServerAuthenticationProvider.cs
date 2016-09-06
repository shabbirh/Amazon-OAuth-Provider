using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CustomAuthorizationServerOAuthProvider.Provider
{
    public interface IAuthorizationServerAuthenticationProvider
    {
        Task Authenticated(AuthorizationServerAuthenticatedContext context);

        Task ReturnEndpoint(AuthorizationServerEndpointContext context);

        void ApplyRedirect(AuthorizationServerApplyRedirectContext context);
    }


}
