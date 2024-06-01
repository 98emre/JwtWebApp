using JwtWebApp.Core.Dtos;
using JwtWebApp.Core.Entities;
using JwtWebApp.Core.Intefaces;
using JwtWebApp.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtWebApp.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }


        public async Task<AuthServiceResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                return new AuthServiceResponseDto(true, "Roles Seeding Is Alread Done");

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));

            return new AuthServiceResponseDto(true, "Roles seeding is Done successfully");

        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.Username);

            if (isExistsUser != null)
            {
                return new AuthServiceResponseDto(false, "Username Already exists");
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.Username,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var createUserResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User creation failed beacuse: ";

                foreach (var error in createUserResult.Errors)
                {
                    errorString += $" # {error.Description}";
                }

                return new AuthServiceResponseDto(false, errorString);
            }

            // Add a Default User Role to all users
            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto(true, "User Created Successfully");
        }


        public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.Username);

            if (user is null)
            {
                return new AuthServiceResponseDto(false, "Invalid Credentials");
            }

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
            {
                return new AuthServiceResponseDto(false, "Invalid Credentials");
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName",user.FirstName),
                new Claim("LastName", user.LastName)
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServiceResponseDto(true, token);

        }

        public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.Username);

            if (user is null)
            {
                return new AuthServiceResponseDto(false, "Invalid User name");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);

            return new AuthServiceResponseDto(true, "User is now an ADMIN");
        }

        public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.Username);

            if (user is null)
            {
                return new AuthServiceResponseDto(false, "Invalid User name");
            }

            await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);

            return new AuthServiceResponseDto(true, "User is now an OWNER");
        }


        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["JWt:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );


            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }

    }
}
