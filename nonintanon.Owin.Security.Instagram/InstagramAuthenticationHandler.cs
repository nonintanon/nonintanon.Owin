using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace nonintanon.Owin.Security.Instagram
{
    internal class InstagramAuthenticationHandler : AuthenticationHandler<InstagramAuthenticationOptions>
    {
        // http://instagram.com/developer/authentication/
        // 

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://api.instagram.com/oauth/access_token";
        //private const string GraphApiEndpoint = "https://api.instagram.com/v1";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public InstagramAuthenticationHandler(HttpClient httpClient, ILogger logger) {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
            AuthenticationProperties properties = null;

            try {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1) {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1) {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger)) {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                string tokenRequest = "grant_type=authorization_code" +
                    "&code=" + Uri.EscapeDataString(code) +
                    "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    "&client_id=" + Uri.EscapeDataString(Options.AppId) +
                    "&client_secret=" + Uri.EscapeDataString(Options.AppSecret);

                //HttpContent content = new FormUrlEncodedContent(new[] {
                //    new KeyValuePair<string, string>("client_id", Uri.EscapeDataString(Options.AppId)),
                //    new KeyValuePair<string, string>("client_secret", Uri.EscapeDataString(Options.AppSecret)),
                //    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                //    new KeyValuePair<string, string>("redirect_uri", Uri.EscapeDataString(redirectUri)),
                //    new KeyValuePair<string, string>("code", Uri.EscapeDataString(code))
                //});

                HttpResponseMessage tokenResponse = await _httpClient.PostAsync("https://api.instagram.com/oauth/access_token/", new StringContent(tokenRequest), Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();
                //IFormCollection form = WebHelpers.ParseForm(text);

                //HttpResponseMessage graphResponse = await _httpClient.GetAsync(GraphApiEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
                //graphResponse.EnsureSuccessStatusCode();
                //text = await graphResponse.Content.ReadAsStringAsync();
                //JObject user = JObject.Parse(text);

                var context = new InstagramAuthenticatedContext(Context, text);
                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id)) {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Username)) {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Username, XmlSchemaString, Options.AuthenticationType));
                    context.Identity.AddClaim(new Claim("urn:instagram:username", context.Username, XmlSchemaString, "instagram"));
                }
                if (!string.IsNullOrEmpty(context.FullName)) {
                    context.Identity.AddClaim(new Claim("urn:instagram:full_name", context.FullName, XmlSchemaString, "instagram"));
                }
                if (!string.IsNullOrEmpty(context.AccessToken)) {
                    context.Identity.AddClaim(new Claim("urn:instagram:access_token", context.AccessToken, XmlSchemaString, "instagram"));
                }
                if (!string.IsNullOrEmpty(context.ProfilePicture)) {
                    context.Identity.AddClaim(new Claim("urn:instagram:profile_picture", context.ProfilePicture, XmlSchemaString, "instagram"));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            } catch (Exception ex) {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync() {
            if (Response.StatusCode != 401) {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null) {
                string baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
                string currentUri = baseUri + Request.Path + Request.QueryString;
                string redirectUri = baseUri + Options.CallbackPath;
                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri)) {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint = "https://api.instagram.com/oauth/authorize/" +
                        "?response_type=code" +
                        "&client_id=" + Uri.EscapeDataString(Options.AppId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                    // TODO "&scope=" + Uri.EscapeDataString(scope) +
                    // scope: 
                    //      basic           = to read any and all data related to a user (e.g. following/followed-by lists, photos, etc.)
                    //      comments        = to create or delete comments on a user's behalf
                    //      relationships   = to follow and unfollow users on a user's behalf
                    //      likes           = to like and unlike items on a user's behalf
                        "&state=" + Uri.EscapeDataString(state);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync() { return await InvokeReplyPathAsync(); }

        private async Task<bool> InvokeReplyPathAsync() {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path) {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null) {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new InstagramReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null) {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal)) {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null) {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null) {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}
