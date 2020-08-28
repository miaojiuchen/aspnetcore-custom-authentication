using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Auth.Authentication;
using Auth.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Auth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly ILogger<ResourceForecastController> _logger;
        private readonly UserManager<User> _userManager;
        public AccountController(ILogger<ResourceForecastController> logger, UserManager<User> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [HttpGet]
        [Route("GetHash")]
        public async Task<string> GetHash(string name)
        {
            var identityUser = await _userManager.FindByNameAsync(name);
            return identityUser.PasswordHash;
        }

        [HttpPost]
        [Route("SignIn")]
        public async Task SignIn([FromBody] LoginCredential credential)
        {
            var identityUser = await _userManager.FindByNameAsync(credential.Username);

            var result = _userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, credential.Password);

            if (result != PasswordVerificationResult.Success)
            {
                throw new InvalidOperationException("Wrong Password");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "Jiuchenm"),
                new Claim(ClaimTypes.Role, identityUser.IsAdmin ? AdminRoleRequirement.AdminRoleName : AdminRoleRequirement.NormalRoleName),
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
        }

        [HttpPost]
        [Route("SignOut")]
        public async Task SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
