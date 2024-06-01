using JwtWebApp.Core.OtherObjects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtWebApp.Controllers
{
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        [HttpGet("Get")]
        public IActionResult Get()
        {
            return Ok(Summaries);
        }

        [HttpGet("GetUserRole")]
        [Authorize(Roles = StaticUserRoles.USER)]
        public IActionResult GetUserRole()
        {
            return Ok(Summaries);
        }

        [HttpGet("GetAdminRole")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public IActionResult GetAdminRole()
        {
            return Ok(Summaries);
        }

        [HttpGet("GetOwnerRole")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public IActionResult GetOwnerRole()
        {
            return Ok(Summaries);
        }
    }
}
