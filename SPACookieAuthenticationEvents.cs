using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace Microsoft.AspNetCore.Authentication.Cookies
{
    /// <summary>
    /// This default implementation of the ICookieAuthenticationEvents may be used if the
    /// application only needs to override a few of the interface methods. This may be used as a base class
    /// or may be instantiated directly.
    /// </summary>
    public class SPACookieAuthenticationEvents : CookieAuthenticationEvents
    {
        public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToLogin(context);

        public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context) => OnRedirectToAccessDenied(context);

        public new Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToLogin { get; set; } = redirectContext =>
        {
            redirectContext.HttpContext.Response.StatusCode = 401;
            return Task.CompletedTask;
        };

        public new Func<RedirectContext<CookieAuthenticationOptions>, Task> OnRedirectToAccessDenied { get; set; } = redirectContext =>
        {
            redirectContext.HttpContext.Response.StatusCode = 403;
            return Task.CompletedTask;
        };
    }
}