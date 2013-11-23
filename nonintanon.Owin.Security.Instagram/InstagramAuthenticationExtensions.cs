using nonintanon.Owin.Security.Instagram;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="InstagramAuthenticationMiddleware"/>
    /// </summary>
    public static class InstagramAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Instagram
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseInstagramAuthentication(this IAppBuilder app, InstagramAuthenticationOptions options) {
            if (app == null) {
                throw new ArgumentNullException("app");
            }
            if (options == null) {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(InstagramAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Instagram
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by Instagram</param>
        /// <param name="appSecret">The appSecret assigned by Instagram</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseInstagramAuthentication(
            this IAppBuilder app, string appId, string appSecret) {
            return UseInstagramAuthentication(app, new InstagramAuthenticationOptions { AppId = appId, AppSecret = appSecret, });
        }
    }
}
