

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Auth.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Auth.Authorization
{
    public class AdminRoleRequirement : AuthorizationHandler<AdminRoleRequirement>, IAuthorizationRequirement
    {
        public const string AdminRoleName = "Admin";
        public const string NormalRoleName = "Normal";
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminRoleRequirement requirement)
        {
            var user = context.User;
            var basicAuthIsAnonymous = user?.Identity == null || !user.Identities.Any(x => x.AuthenticationType == AuthenticationConstants.BasicAuthScheme && x.IsAuthenticated);
            if (!basicAuthIsAnonymous)
            {
                var userIdentity = user.Identities.First(x => x.AuthenticationType == AuthenticationConstants.BasicAuthScheme && x.IsAuthenticated);
                if (userIdentity.Claims.First(x => x.Type == ClaimTypes.Role).Value == AdminRoleName)
                {
                    context.Succeed(requirement);
                }
            }
            return Task.CompletedTask;
        }

        public override string ToString()
        {
            return $"{nameof(AdminRoleRequirement)}: Requires an authenticated user with admin claim.";
        }
    }
}