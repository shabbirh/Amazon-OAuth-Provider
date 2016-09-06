using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CustomAuthorizationServerOAuthProvider.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace CustomAuthorizationServerOAuthProvider
{
    public class AuthorizationServerAuthenticationOptions : AuthenticationOptions
    {
        public AuthorizationServerAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            CallbackPath = new PathString("/signin-authsrvr");
            Caption = Constants.DefaultAuthenticationType;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            BackchannelCertificateValidator = new AuthorizationServerSelfSignedCertificateValidator();
        }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public IAuthorizationServerAuthenticationProvider Provider { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
