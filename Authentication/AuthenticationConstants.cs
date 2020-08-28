using Microsoft.AspNetCore.Authentication.Cookies;

namespace Auth.Authentication
{
    public static class AuthenticationConstants
    {
        public const string BasicAuthScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        public const string OAuthGithubScheme = "OAuthGithub";

        public const string OAuthGithubCookieScheme = "OAuthGithubCookie";
        public const string BasicAuthCookieScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        public const string AdminPolicyName = "AdminPolicy";
        public const string OAuthGithubPolicyName = "OAuthGithubPolicy";
        
        public const string BasicAuthCookieName = "BasicAuthCookie";
        public const string OAuthGithubCookieName = "OAuthGithubCookie";
    }
}