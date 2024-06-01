using System.ComponentModel.DataAnnotations;

namespace JwtWebApp.Core.Dtos
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Useranme is required")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
