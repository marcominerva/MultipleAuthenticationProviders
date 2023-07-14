using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace MultipleAuthenticationProviders.Authentication;

public class ClaimsTransformer : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity;
        var claims = new List<Claim>();

        if (identity.IsAuthenticated)
        {
            claims.Add(new Claim(ClaimTypes.Role, "Administrator"));
        }

        identity.AddClaims(claims);

        return Task.FromResult(principal);
    }
}
