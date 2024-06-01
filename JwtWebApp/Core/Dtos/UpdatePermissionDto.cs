using System.ComponentModel.DataAnnotations;

namespace JwtWebApp.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Useranme is required")]
        public string Username { get; set; }
    }
}
