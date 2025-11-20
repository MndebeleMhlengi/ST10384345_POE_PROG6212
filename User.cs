using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;

namespace CMCS.Models
{
    public class User
    {
        internal DateTime LastModifiedDate;

        [Key]
        public int UserId { get; set; }

        [Required]
        [StringLength(50)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(50)]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        [StringLength(100)]
        public string Email { get; set; }

        [Required]
        [StringLength(100)]
        public string Password { get; set; }

        [Required]
        public UserRole Role { get; set; }

        [Phone]
        public string PhoneNumber { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.Now;

        public DateTime? LastLoginDate { get; set; }

        public bool IsActive { get; set; } = true;

        [StringLength(100)]
        public string Department { get; set; }

        [Range(0, double.MaxValue)]
        public decimal HourlyRate { get; set; }

        [StringLength(20)]
        public string EmployeeNumber { get; set; }

        // Navigation properties
        public virtual ICollection<Claim> Claims { get; set; }
        public virtual ICollection<ClaimApproval> Approvals { get; set; }
    }
}