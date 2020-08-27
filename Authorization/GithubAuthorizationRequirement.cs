using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

public class GithubDenyAnonymousAuthorizationRequirement : AuthorizationHandler<GithubDenyAnonymousAuthorizationRequirement>, IAuthorizationRequirement
{
    /// <summary>
    /// Makes a decision if authorization is allowed based on a specific requirement.
    /// </summary>
    /// <param name="context">The authorization context.</param>
    /// <param name="requirement">The requirement to evaluate.</param>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, GithubDenyAnonymousAuthorizationRequirement requirement)
    {
        var user = context.User;
        var userIsAnonymous =
            user?.Identity == null ||
            !user.Identities.Any(i => i.IsAuthenticated);
        if (!userIsAnonymous)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }

    public override string ToString()
    {
        return $"{nameof(GithubDenyAnonymousAuthorizationRequirement)}: Requires an Github authenticated user.";
    }
}