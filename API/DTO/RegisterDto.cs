using System.ComponentModel.DataAnnotations;

namespace API.DTO
{
    public class RegisterDto
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}