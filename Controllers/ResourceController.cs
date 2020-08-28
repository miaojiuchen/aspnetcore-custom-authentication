using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Auth.Authentication;
using Auth.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Auth.Controllers
{
    [ApiController]
    [Route("resource")]
    public class ResourceForecastController : ControllerBase
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public ResourceForecastController(ILogger<ResourceForecastController> logger, IDataProtectionProvider protectionProvider)
        {
            _dataProtectionProvider = protectionProvider;
        }

        [HttpGet]
        [Route("protected_by_admin_policy")]
        [Authorize(AuthenticationConstants.AdminPolicyName)]
        public string Get()
        {
            return "Now you see me";
        }

        [HttpGet]
        [Route("GetGithub")]
        [Authorize(AuthenticationConstants.OAuthGithubPolicyName)]
        public object GetGithub()
        {
            return HttpContext.User.Claims.Select(x => new { x.Type, x.Value });
        }

        [HttpGet]
        [Authorize]
        [Route("unsafe_GetCookieDecoded")]
        public object GetDecode(string cookieKey, string schema)
        {
            var securedValue = HttpContext.Request.Cookies.First(x => x.Key == cookieKey).Value;

            var protectedData = Base64UrlTextEncoder.Decode(securedValue);

            var protector = _dataProtectionProvider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", schema, "v2");

            var userData = protector.Unprotect(protectedData);

            var deserialized = TicketSerializer.Default.Deserialize(userData);

            return new
            {
                Claims = deserialized.Principal.Claims.Select(x => new { x.Type, x.Value }),
                Properties = deserialized.Properties,
                Identities = deserialized.Principal.Identities.Select(x => new { x.AuthenticationType, x.Name })
            };
        }
    }
}
