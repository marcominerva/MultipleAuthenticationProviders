﻿using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;

namespace MultipleAuthenticationProviders.Authentication;

public class ClaimsTransformer(IMemoryCache memoryCache) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity;

        if (identity.IsAuthenticated)
        {
            var claims = await memoryCache.GetOrCreateAsync(identity.Name, (entry) =>
            {
                // Retrieve claims from database...
                var claimsFromDb = new List<Claim>() { new(ClaimTypes.Role, "Administrator") };

                var unixTime = Convert.ToInt64(identity.FindFirst("exp")?.Value);
                var expirationDateTime = DateTimeOffset.FromUnixTimeSeconds(unixTime);
                entry.AbsoluteExpiration = expirationDateTime;

                return Task.FromResult(claimsFromDb);
            });

            identity.AddClaims(claims);
        }

        return principal;
    }
}