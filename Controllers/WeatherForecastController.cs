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
    [Route("weather")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;

        private readonly IDataProtectionProvider _protectionProvider;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, IDataProtectionProvider protectionProvider)
        {
            _logger = logger;
            _protectionProvider = protectionProvider;
        }

        [HttpGet]
        [Authorize(AdminAuthorizationRequirement.AdminRoleName)]
        public IEnumerable<WeatherForecast> Get()
        {
            var rng = new Random();
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = rng.Next(-20, 55),
                Summary = Summaries[rng.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [HttpGet]
        [Authorize]
        [Route("unsafe_GetCookieDecoded")]
        public object GetDecode()
        {
            var securedValue = HttpContext.Request.Cookies.First(x => x.Key == CookieBuildOptions.AuthenticationCookieName).Value;

            var protectedData = Base64UrlTextEncoder.Decode(securedValue);

            var protector = _protectionProvider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", CookieAuthenticationDefaults.AuthenticationScheme, "v2");

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
