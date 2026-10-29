# Multiple Authentication Providers

Sample ASP.NET Core Web API that accepts two different bearer token types in the same application:

- **Local JWT tokens**, issued by the application with [SimpleAuthentication](https://github.com/marcominerva/SimpleAuthentication).
- **Microsoft Entra ID access tokens**, validated with [Microsoft.Identity.Web](https://github.com/AzureAD/microsoft-identity-web).

The application uses an ASP.NET Core policy authentication scheme to inspect the incoming `Authorization` header and dynamically forward each request to the right JWT bearer handler.

## Project structure

```text
MultipleAuthenticationProviders/
|-- MultipleAuthenticationProviders.slnx
|-- README.md
`-- MultipleAuthenticationProviders/
    |-- Program.cs
    |-- appsettings.json
    |-- appsettings.Development.json
    |-- appsettings.local.json
    |-- Authentication/
    |   `-- ClaimsTransformer.cs
    |-- Models/
    |   |-- LoginRequest.cs
    |   `-- LoginResponse.cs
    `-- Settings/
        `-- AzureAdSettings.cs
```

### `Program.cs`

Contains the whole minimal API setup:

- loads `appsettings.local.json` as an optional local override file;
- registers memory caching;
- configures a policy authentication scheme named `Authentication`;
- registers the local JWT provider with `AddSimpleAuthentication`;
- registers Microsoft Entra ID JWT validation with `AddMicrosoftIdentityWebApi`;
- configures OpenAPI and Swagger UI with both local bearer authentication and OAuth2;
- exposes:
  - `POST /api/auth/login`, which returns a local JWT token;
  - `GET /api/me`, which requires authentication and returns the current user state.

### `Models`

Contains the request and response contracts used by the local login endpoint:

- `LoginRequest`: username and password payload.
- `LoginResponse`: generated local JWT token.

### `Settings`

Contains `AzureAdSettings`, which maps the `AzureAd` configuration section used by Microsoft Entra ID and Swagger UI.

### `Authentication`

Contains `ClaimsTransformer`, an example of a global claims transformation component. The current setup adds custom claims for Entra-authenticated users directly in the Entra JWT bearer `OnTokenValidated` event in `Program.cs`, so the transformer registration is commented out.

## Authentication flow

The default authentication and challenge scheme is `Authentication`, a policy scheme:

```csharp
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "Authentication";
    options.DefaultChallengeScheme = "Authentication";
})
.AddPolicyScheme("Authentication", "Authentication", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        // Selects the real authentication handler.
    };
});
```

At runtime:

1. The API receives a request with an `Authorization` header containing a bearer token.
2. The policy scheme reads the JWT issuer without validating the token.
3. If the issuer is recognized as Microsoft Entra ID, the request is forwarded to the default JWT bearer scheme, `Bearer`.
4. Otherwise, the request is forwarded to the local SimpleAuthentication scheme, `LocalBearer`.
5. The selected handler validates the token and creates the `ClaimsPrincipal`.

The token is only inspected by the selector to choose the validation handler. The actual token validation is still performed by the selected JWT bearer handler.

## Configuration

Configuration lives in `MultipleAuthenticationProviders/appsettings.json`. Use `appsettings.local.json` for local secrets and machine-specific values. This file is loaded after `appsettings.json`, so it can override any setting.

### Microsoft Entra ID

Configure the `AzureAd` section with the values from your app registration:

```json
{
  "AzureAd": {
    "Instance": "https://login.microsoftonline.com/",
    "Domain": "contoso.onmicrosoft.com",
    "TenantId": "<tenant-id>",
    "ClientId": "<api-application-client-id>",
    "Scopes": [
      "api.access"
    ]
  }
}
```

| Setting | Description |
|---|---|
| `Instance` | Microsoft identity platform base URL. Usually `https://login.microsoftonline.com/`. |
| `Domain` | Tenant domain, for example `contoso.onmicrosoft.com`. |
| `TenantId` | Tenant ID or tenant name used to validate tokens. |
| `ClientId` | Application/client ID of the protected API app registration. |
| `Scopes` | API scopes exposed by the app registration, without the `api://{ClientId}/` prefix. |

Swagger UI uses these values to build the OAuth2 authorization and token URLs and to request scopes in the format:

```text
api://{ClientId}/{scope}
```

For example, with `ClientId` set to `11111111-1111-1111-1111-111111111111` and `Scopes` containing `api.access`, Swagger requests:

```text
api://11111111-1111-1111-1111-111111111111/api.access
```

### Local JWT authentication

Configure the `Authentication:JwtBearer` section for SimpleAuthentication:

```json
{
  "Authentication": {
    "DefaultScheme": "Bearer",
    "JwtBearer": {
      "SchemeName": "LocalBearer",
      "SecurityKey": "<strong-signing-key>",
      "Issuers": [
        "issuer"
      ],
      "Audiences": [
        "audience"
      ],
      "ExpirationTime": "01:00:00",
      "ClockSkew": "00:05:00"
    }
  }
}
```

| Setting | Description |
|---|---|
| `SchemeName` | Authentication scheme registered for local JWT tokens. The sample uses `LocalBearer`. |
| `SecurityKey` | Symmetric signing key used to issue and validate local JWT tokens. Store real values outside source control. |
| `Issuers` | Valid local JWT issuers. |
| `Audiences` | Valid local JWT audiences. |
| `ExpirationTime` | Default lifetime for tokens created by `IJwtBearerService`. |
| `ClockSkew` | Allowed clock skew during lifetime validation. |
| `EnableJwtBearerService` | Enables `IJwtBearerService`, used by the login endpoint to create local JWT tokens. |

## Local settings

Create `MultipleAuthenticationProviders/appsettings.local.json` to override sensitive or environment-specific values:

```json
{
  "AzureAd": {
    "TenantId": "<tenant-id>",
    "ClientId": "<api-application-client-id>"
  },
  "Authentication": {
    "JwtBearer": {
      "SecurityKey": "<local-development-signing-key>"
    }
  }
}
```

Do not commit real signing keys, tenant-specific secrets, or production values.

## Endpoints

### Create a local JWT token

```http
POST /api/auth/login
Content-Type: application/json

{
  "userName": "alice",
  "password": "password"
}
```

The sample does not implement real credential validation. The endpoint shows where application-specific login checks should be added before issuing a local JWT token.

### Get current user information

```http
GET /api/me
Authorization header: YOUR_ACCESS_TOKEN
```

The token can be either:

- a local token created by `POST /api/auth/login`;
- a Microsoft Entra ID access token for the configured API.

## Adding custom claims for Entra users

Local JWT tokens can include custom claims when they are created during login. For Entra tokens, the sample adds application-specific claims after token validation:

```csharp
builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters.NameClaimType = "preferred_username";
    options.TokenValidationParameters.RoleClaimType = "roles";

    var existingOnTokenValidated = options.Events.OnTokenValidated;
    options.Events.OnTokenValidated = async context =>
    {
        await existingOnTokenValidated(context);

        if (context.Principal?.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
        {
            return;
        }

        var memoryCache = context.HttpContext.RequestServices.GetRequiredService<IMemoryCache>();
        var userId = context.Principal.GetObjectId()!;

        var claims = await memoryCache.GetOrCreateAsync($"entra:{userId}", entry =>
        {
            entry.AbsoluteExpiration = context.SecurityToken.ValidTo;

            // Retrieve claims from database...
            return Task.FromResult<List<Claim>>([new(identity.RoleClaimType, "Administrator")]);
        });

        identity.AddClaims(claims!);
    };
});
```

These claims are added only to the server-side `ClaimsPrincipal`. They are not written back into the Entra JWT token. If the claims must be present inside the token itself, configure them in Microsoft Entra ID, for example with app roles or a custom claims provider.

## Running the sample

From the repository root:

```powershell
dotnet run --project .\MultipleAuthenticationProviders\MultipleAuthenticationProviders.csproj
```

Then open the Swagger UI URL shown in the console output.
