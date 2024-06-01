using JwtWebApp.Core.Dtos;
using JwtWebApp.Core.Entities;
using JwtWebApp.Core.Intefaces;
using JwtWebApp.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }


        [HttpPost("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRoles = await _authService.SeedRolesAsync();

            return Ok(seedRoles.Message);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authService.RegisterAsync(registerDto);

            if (registerResult.IsSucced)
            {
                return Ok(registerResult.Message);
            }

            return BadRequest(registerResult.Message);
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authService.LoginAsync(loginDto);

            if (loginResult.IsSucced)
            {
                return Ok(loginResult.Message);
            }

            return Unauthorized(loginResult.Message);
        }



        [HttpPost("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeAdminAsync(updatePermissionDto);

            if (operationResult.IsSucced)
            {
                return Ok(operationResult.Message);
            }

            return BadRequest(operationResult.Message);
        }


        [HttpPost("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authService.MakeOwnerAsync(updatePermissionDto);

            if (operationResult.IsSucced)
            {
                return Ok(operationResult.Message);
            }

            return BadRequest(operationResult.Message);

        }


    }
}
