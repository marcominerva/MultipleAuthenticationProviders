using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Identity.Web;
using MultipleAuthenticationProviders.Authentication;
using MultipleAuthenticationProviders.Settings;
using MultipleAuthenticationProviders.Swagger;
using SimpleAuthentication;
using TinyHelpers.AspNetCore.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var azureAdSettings = builder.Services.ConfigureAndGet<AzureAdSettings>(builder.Configuration, "AzureAd");

builder.Services.AddControllers();

builder.Services.AddMicrosoftIdentityWebApiAuthentication(builder.Configuration);

JwtSecurityTokenHandler.DefaultMapInboundClaims = false;
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
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();

    app.UseSwaggerUI(options =>
    {
        options.OAuthClientId(azureAdSettings.ClientId);
        options.OAuthScopes(azureAdSettings.Scopes.Select(scope => $"api://{azureAdSettings.ClientId}/{scope}").ToArray());
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
