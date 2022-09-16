﻿using Microsoft.EntityFrameworkCore;
using VerifyEmailForgotPass.Entities;

namespace VerifyEmailForgotPass.Data
{
    public class DataContext: DbContext
    {
        public DataContext(DbContextOptions<DataContext> options): base(options)
        {
    
        }

        public DbSet<User> Users => Set<User>();
    }
}