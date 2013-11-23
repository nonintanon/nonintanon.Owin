using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;

namespace nonintanon.Owin.Security.Instagram
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class InstagramAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="InstagramAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Instagram Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public InstagramAuthenticatedContext(IOwinContext context, string oauthTokenResponse)
            : base(context) {

            dynamic token = JObject.Parse(oauthTokenResponse);
            this.AccessToken = token.access_token;
            this.Id = token.user.id;
            this.Username = token.user.username;
            this.FullName = token.user.full_name;
            this.ProfilePicture = token.user.profile_picture;
        }

        /// <summary>
        /// Gets the Instagram user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Instagram username
        /// </summary>
        public string Username { get; private set; }

        ///// <summary>
        ///// Gets the user's name
        ///// </summary>
        public string FullName { get; private set; }

        ///// <summary>
        ///// Gets the user's profile picture
        ///// </summary>
        public string ProfilePicture { get; private set; }

        /// <summary>
        /// Gets the Instagram access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
