using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
        [Authorize]
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
        [Route("GetDecode")]
        public object GetDecode()
        {
            // Console.WriteLine(HttpContext.Request.Cookies.First(x => x.Key == ".AspNetCore.Cookies").Value);
            var protectedData = Base64UrlTextEncoder.Decode("CfDJ8ARBIV43isBFi0u3uT9Osau7GudS9c2nTsZvgZF-ugOymNRpRKPUTdB_CNlbO7CN1AVTK48FaP1yIzDOFLEkX9LxL95U3DfwWYMWxEj_v0yumzC1Xi3-rs1SlDwyanNNsYI_oU4n_aqLA4hoJGy2yh1A6zw9wePU4cFCSLJ7IwpkwO5hn0Kurk18Bsn17pOfjZJMycIZVAJ_qk11DmSZfbBghPhmMJqkpxALLWkLWWu4-GaouO1c71zpwW-Ce7G0cPzhebJDyHfdMc9kEVTSxce87ITW3iVQLyFofRMUbAA7");

            var protector = _protectionProvider.CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", CookieAuthenticationDefaults.AuthenticationScheme, "v2").CreateProtector("v3").CreateProtector("v4");

            var userData = protector.Unprotect(protectedData);

            var deserialized = TicketSerializer.Default.Deserialize(userData);

            return new
            {
                Claims = deserialized.Principal.Claims.Select(x => new { Name = x.Type, Value = x.Value }),
                Properties = deserialized.Properties
            };
        }
    }
}
