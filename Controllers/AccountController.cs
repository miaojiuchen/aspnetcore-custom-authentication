using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Auth.Authentication;
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
        private readonly ILogger<WeatherForecastController> _logger;
        private readonly UserManager<User> _userManager;
        public AccountController(ILogger<WeatherForecastController> logger, UserManager<User> userManager)
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
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, "Jiuchenm"),
                new Claim("LastChanged", "")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var identityUser = await _userManager.FindByNameAsync(credential.Username);

            var result = _userManager.PasswordHasher.VerifyHashedPassword(identityUser, identityUser.PasswordHash, credential.Password);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
        }

        [HttpPost]
        public async Task SignOut()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
