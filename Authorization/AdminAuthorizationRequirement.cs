

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
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminAuthorizationRequirement requirement)
        {
            if (context.User.Identity.IsAuthenticated && context.User.Claims.First(x => x.Type == ClaimTypes.Role).Value == "Admin")
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