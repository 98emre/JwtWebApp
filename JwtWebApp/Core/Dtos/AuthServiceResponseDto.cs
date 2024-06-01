namespace JwtWebApp.Core.Dtos
{
    public class AuthServiceResponseDto
    {
        public bool IsSucced { get; set; }

        public string Message { get; set; }

        public AuthServiceResponseDto(bool isSucced, string message)
        {
            IsSucced = isSucced;
            Message = message;
        }
    }
}
