

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Auth.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

namespace Auth.Authorization
{
    public class AdminAuthorizationRequirement : AuthorizationHandler<AdminAuthorizationRequirement>, IAuthorizationRequirement
    {
        public const string AdminRoleName = "Admin";
        public const string NormalRoleName = "Normal";
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminAuthorizationRequirement requirement)
        {
            var user = context.User;
            var userIsAnonymous = user?.Identity == null || !user.Identities.Any(x => x.IsAuthenticated);
            if (!userIsAnonymous && context.User.Claims.First(x => x.Type == ClaimTypes.Role).Value == AdminRoleName)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }

        public override string ToString()
        {
            return $"{nameof(AdminAuthorizationRequirement)}: Requires an authenticated user with admin claim.";
        }
    }
}