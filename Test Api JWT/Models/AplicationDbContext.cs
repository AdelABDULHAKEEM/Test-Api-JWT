using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test_Api_JWT.Models
{
    public class AplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public AplicationDbContext(DbContextOptions<AplicationDbContext> options) :base (options)
        {

        }

    }
}
