using Microsoft.EntityFrameworkCore;
using CMCS.Models;
using System.Collections.Generic;
using System.Reflection.Emit;

namespace CMCS.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<Claim> Claims { get; set; }
        public DbSet<Document> Documents { get; set; }
        public DbSet<ClaimApproval> ClaimApprovals { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Configure User entity
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();

            // Configure Claim entity
            modelBuilder.Entity<Claim>()
                .Property(c => c.TotalAmount)
                .HasComputedColumnSql("[HoursWorked] * [HourlyRate]");

            // Configure relationships
            modelBuilder.Entity<Claim>()
                .HasOne(c => c.Lecturer)
                .WithMany(u => u.Claims)
                .HasForeignKey(c => c.LecturerId);

            modelBuilder.Entity<Document>()
                .HasOne(d => d.Claim)
                .WithMany(c => c.Documents)
                .HasForeignKey(d => d.ClaimId);

            modelBuilder.Entity<ClaimApproval>()
                .HasOne(ca => ca.Claim)
                .WithMany(c => c.Approvals)
                .HasForeignKey(ca => ca.ClaimId);

            modelBuilder.Entity<ClaimApproval>()
                .HasOne(ca => ca.Approver)
                .WithMany(u => u.Approvals)
                .HasForeignKey(ca => ca.ApproverId)
                .OnDelete(DeleteBehavior.NoAction); // This is the corrected line

            base.OnModelCreating(modelBuilder);
        }
    }
}