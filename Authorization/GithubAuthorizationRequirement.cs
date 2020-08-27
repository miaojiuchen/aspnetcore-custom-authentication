using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

public class DenyGithubAnonymousAuthorizationRequirement : AuthorizationHandler<DenyGithubAnonymousAuthorizationRequirement>, IAuthorizationRequirement
{
    /// <summary>
    /// Makes a decision if authorization is allowed based on a specific requirement.
    /// </summary>
    /// <param name="context">The authorization context.</param>
    /// <param name="requirement">The requirement to evaluate.</param>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DenyGithubAnonymousAuthorizationRequirement requirement)
    {
        var user = context.User;
        var userIsAnonymous =
            user?.Identity == null ||
            !user.Identities.Any(i => i.AuthenticationType == "OAuth-Github" && i.IsAuthenticated);
        if (!userIsAnonymous)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }

    public override string ToString()
    {
        return $"{nameof(DenyGithubAnonymousAuthorizationRequirement)}: Requires an Github authenticated user.";
    }
}