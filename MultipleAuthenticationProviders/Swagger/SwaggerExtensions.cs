using Microsoft.OpenApi.Models;
using MultipleAuthenticationProviders.Settings;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace MultipleAuthenticationProviders.Swagger;

public static class SwaggerExtensions
{
    public static void AddOAuth2Authorization(this SwaggerGenOptions options, AzureAdSettings azureAdSettings)
    {
        options.AddSecurityDefinition("OAuth2", new()
        {
            Type = SecuritySchemeType.OAuth2,
            Flows = new()
            {
                Implicit = new()
                {
                    AuthorizationUrl = new Uri($"{azureAdSettings.Instance}{azureAdSettings.TenantId}/oauth2/v2.0/authorize"),
                    TokenUrl = new Uri($"{azureAdSettings.Instance}{azureAdSettings.TenantId}/oauth2/v2.0/token"),
                    Scopes = azureAdSettings.Scopes.ToDictionary(scope => $"api://{azureAdSettings.ClientId}/{scope}", scope => $"Access to {scope}")
                }
            }
        });
    }
}
