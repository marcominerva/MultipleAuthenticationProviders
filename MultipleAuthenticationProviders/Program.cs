using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Web;
using Microsoft.Net.Http.Headers;
using MultipleAuthenticationProviders.Authentication;
using MultipleAuthenticationProviders.Models;
using MultipleAuthenticationProviders.Settings;
using MultipleAuthenticationProviders.Swagger;
using SimpleAuthentication;
using SimpleAuthentication.JwtBearer;
using TinyHelpers.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var azureAdSettings = builder.Services.ConfigureAndGet<AzureAdSettings>(builder.Configuration, "AzureAd");

builder.Services.AddMemoryCache();
builder.Services.AddControllers();

builder.Services
.AddAuthentication(options =>
{
    options.DefaultScheme = "CustomAuth";
    options.DefaultChallengeScheme = "CustomAuth";
})
.AddPolicyScheme("CustomAuth", "CustomAuth", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        string authorization = context.Request.Headers[HeaderNames.Authorization];
        if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
        {
            var token = authorization["Bearer ".Length..].Trim();
            var jwtHandler = new JwtSecurityTokenHandler();

            // It's a self contained access token and not encrypted
            if (jwtHandler.CanReadToken(token))
            {
                var issuer = jwtHandler.ReadJwtToken(token).Issuer;
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

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.AddOAuth2Authorization(azureAdSettings);
    options.AddSimpleAuthentication(builder.Configuration, additionalSecurityDefinitionNames: new[] { "OAuth2" });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    app.UseStaticFiles();

    app.UseSwagger();

    app.UseSwaggerUI(options =>
    {
        options.InjectStylesheet("/css/swagger.css");
        options.OAuthClientId(azureAdSettings.ClientId);
        options.OAuthScopes(azureAdSettings.Scopes.Select(scope => $"api://{azureAdSettings.ClientId}/{scope}").ToArray());
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/api/auth/login", (LoginRequest request, IJwtBearerService jwtBearerService, IMemoryCache memoryCache) =>
{
    // Checks for login...

    var token = jwtBearerService.CreateToken(request.UserName);
    memoryCache.Remove(request.UserName);

    return TypedResults.Ok(new LoginResponse(token));
});

app.MapControllers();

app.Run();
