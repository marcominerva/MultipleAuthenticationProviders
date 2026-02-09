using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;
using MultipleAuthenticationProviders.Authentication;
using MultipleAuthenticationProviders.Models;
using MultipleAuthenticationProviders.Settings;
using SimpleAuthentication;
using SimpleAuthentication.JwtBearer;
using TinyHelpers.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile("appsettings.local.json", optional: true, reloadOnChange: true);

// Add services to the container.
var azureAdSettings = builder.Services.ConfigureAndGet<AzureAdSettings>(builder.Configuration, "AzureAd");

builder.Services.AddControllers();
builder.Services.AddMemoryCache();

builder.Services
.AddAuthentication(options =>
{
    options.DefaultScheme = "Authentication";
    options.DefaultChallengeScheme = "Authentication";
})
.AddPolicyScheme("Authentication", "Authentication", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        string authorization = context.Request.Headers[HeaderNames.Authorization];
        if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
        {
            var token = authorization["Bearer ".Length..].Trim();
            var jwtHandler = new JsonWebTokenHandler();

            // It's a self contained access token and not encrypted
            if (jwtHandler.CanReadToken(token))
            {
                var issuer = jwtHandler.ReadJsonWebToken(token).Issuer;
                if (issuer.StartsWith("https://login.microsoftonline.com/"))
                {
                    return JwtBearerDefaults.AuthenticationScheme;
                }
            }
        }

        // We don't know what it is, assume it's a local bearer token
        return "LocalBearer";
    };
})
.AddSimpleAuthentication(builder.Configuration)
.AddMicrosoftIdentityWebApi(builder.Configuration);

//JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
//JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Add("preferred_username", ClaimTypes.Name);

builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters.NameClaimType = "preferred_username";
    options.TokenValidationParameters.RoleClaimType = "roles";
});

builder.Services.AddTransient<IClaimsTransformation, ClaimsTransformer>();

builder.Services.AddOpenApi(options =>
{
    options.AddSimpleAuthentication(builder.Configuration);
    options.AddOAuth2Authentication("OAuth2", new()
    {
        AuthorizationUrl = new Uri($"{azureAdSettings.Instance}{azureAdSettings.TenantId}/oauth2/v2.0/authorize"),
        TokenUrl = new Uri($"{azureAdSettings.Instance}{azureAdSettings.TenantId}/oauth2/v2.0/token"),
        //Scopes = azureAdSettings.Scopes.ToDictionary(scope => $"api://{azureAdSettings.ClientId}/{scope}", scope => $"Access to {scope}")
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

app.MapOpenApi();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/v1.json", builder.Environment.ApplicationName);
    options.OAuthClientId(azureAdSettings.ClientId);
    //options.OAuthScopes(azureAdSettings.Scopes.Select(scope => $"api://{azureAdSettings.ClientId}/{scope}").ToArray());
});

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", async (LoginRequest request, IJwtBearerService jwtBearerService, IMemoryCache memoryCache) =>
{
    // Checks for login...

    var token = await jwtBearerService.CreateTokenAsync(request.UserName);
    memoryCache.Remove(request.UserName);

    return TypedResults.Ok(new LoginResponse(token));
})
.ProducesProblem(StatusCodes.Status400BadRequest);

app.MapControllers();

app.Run();
