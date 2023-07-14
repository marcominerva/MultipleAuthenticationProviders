using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MultipleAuthenticationProviders.Controllers;

[ApiController]
[Route("api/[controller]")]
public class MeController : ControllerBase
{
    [Authorize]
    [HttpGet]
    public IActionResult Get()
    {
        var user = new
        {
            IsLogged = User.Identity.IsAuthenticated
        };

        return Ok(user);
    }
}
