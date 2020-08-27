using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Auth.Authentication;
using Auth.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Auth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddTransient<SPACookieAuthenticationEvents>();

            services.AddTransient<IUserStore<User>, UserStore>();

            services.AddIdentityCore<User>();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.Cookie.Name = "basic-auth";
                    options.EventsType = typeof(SPACookieAuthenticationEvents);
                });

            services.AddControllers();

            services.AddRazorPages(options =>
            {
                options.Conventions.AuthorizePage("/UserInfo", "Github");
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy("Admin", policy =>
                {
                    policy.Requirements.Add(new AdminAuthorizationRequirement());
                });

                options.AddPolicy("OAuth-Github", policy =>
                {
                    policy.RequireAuthenticatedUser();
                });
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = AuthenticationSchemeConstants.OAuthGithubCookieScheme;
                options.DefaultChallengeScheme = AuthenticationSchemeConstants.OAuthGithubScheme;
            })
            .AddCookie(AuthenticationSchemeConstants.OAuthGithubCookieScheme, options =>
              {
                  options.Cookie.Name = "oauth-github";
              })
            .AddOAuth(AuthenticationSchemeConstants.OAuthGithubScheme, options =>
            {
                options.ClientId = "d540b7fcd950430e61cc";
                options.ClientSecret = "1f8f30562f2541da8e1d748fe573627476fa468c";
                options.CallbackPath = new PathString("/oauth-github-callback");

                options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
                options.TokenEndpoint = "https://github.com/login/oauth/access_token";
                options.UserInformationEndpoint = "https://api.github.com/user";

                options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
                options.ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
                options.ClaimActions.MapJsonKey("urn:github:login", "login");
                options.ClaimActions.MapJsonKey("urn:github:url", "html_url");
                options.ClaimActions.MapJsonKey("urn:github:avatar", "avatar_url");

                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = async context =>
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);

                        var response = await context.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        var responseJson = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync());

                        responseJson.WriteTo(new Utf8JsonWriter(Console.OpenStandardOutput(), new JsonWriterOptions { Indented = true }));

                        context.RunClaimActions(responseJson.RootElement);
                    }
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
                endpoints.MapRazorPages();
            });
        }
    }
}
