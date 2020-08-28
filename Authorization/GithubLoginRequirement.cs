

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Auth.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Auth.Authorization
{
    public class GithubLoginRequirement : AuthorizationHandler<GithubLoginRequirement>, IAuthorizationRequirement
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, GithubLoginRequirement requirement)
        {
            var user = context.User;
            var githubIsAnonymous = user?.Identity == null || !user.Identities.Any(x => x.AuthenticationType == AuthenticationConstants.OAuthGithubScheme && x.IsAuthenticated);
            if (!githubIsAnonymous)
            {
                context.Succeed(requirement);
            }
            return Task.CompletedTask;
        }

        public override string ToString()
        {
            return $"{nameof(GithubLoginRequirement)}: Requires an authenticated user with Github login.";
        }
    }
}