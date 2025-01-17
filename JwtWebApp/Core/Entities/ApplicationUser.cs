﻿using Microsoft.AspNetCore.Identity;

namespace JwtWebApp.Core.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }
    }
}
