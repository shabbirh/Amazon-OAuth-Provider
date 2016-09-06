using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace CustomAuthorizationServerOAuthProvider.Provider
{
    public class AuthorizationServerAuthenticatedContext : BaseContext
    {
        public AuthorizationServerAuthenticatedContext(
            IOwinContext context, JObject user, string accessToken, string expires, string refreshToken) : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "user_id");
            Email = TryGetValue(user, "email");
            Name = TryGetValue(user, "name");
        }

        public string AccessToken { get; private set; }

        public TimeSpan? ExpiresIn { get; private set; }

        public string RefreshToken { get; private set; }

        public string Id { get; private set; }

        public string Email { get; private set; }

        public string Name { get; private set; }

        public ClaimsIdentity Identity { get; set; }

        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}