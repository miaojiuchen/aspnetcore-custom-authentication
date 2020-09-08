using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Auth.Authentication;
using Auth.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

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

            services.AddAuthentication(AuthenticationConstants.BasicAuthScheme)
                .AddCookie(AuthenticationConstants.BasicAuthScheme, options =>
                {
                    options.Cookie.Name = AuthenticationConstants.BasicAuthCookieName;
                    options.EventsType = typeof(SPACookieAuthenticationEvents);
                    options.Cookie.Expiration = TimeSpan.FromDays(3);
                    options.ExpireTimeSpan = TimeSpan.FromDays(3);
                });

            services.AddControllers();

            services.AddRazorPages(options =>
            {
                options.Conventions.AuthorizePage("/UserInfo", AuthenticationConstants.OAuthGithubPolicyName);
            });

            services.AddAuthorization(options =>
            {
                options.AddPolicy(AuthenticationConstants.AdminPolicyName, policy =>
                {
                    policy.Requirements.Add(new AdminRoleRequirement());
                });

                options.AddPolicy(AuthenticationConstants.OAuthGithubPolicyName, policy =>
                {
                    policy.Requirements.Add(new GithubLoginRequirement());
                });
            });

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = AuthenticationConstants.OAuthGithubCookieScheme;
                options.DefaultChallengeScheme = AuthenticationConstants.OAuthGithubScheme;
            })
            .AddCookie(AuthenticationConstants.OAuthGithubCookieScheme, options =>
              {
                  options.Cookie.Name = AuthenticationConstants.OAuthGithubCookieName;
              })
            .AddOAuth(AuthenticationConstants.OAuthGithubScheme, options =>
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

                        var responseText = await response.Content.ReadAsStringAsync();
                        var responseJson = JsonDocument.Parse(responseText);

                        var jsonWriter = new Utf8JsonWriter(Console.OpenStandardOutput(), new JsonWriterOptions { Indented = true });
                        responseJson.WriteTo(jsonWriter);
                        jsonWriter.Flush();

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
