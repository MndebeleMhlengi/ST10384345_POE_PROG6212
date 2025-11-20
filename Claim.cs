using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Reflection.Metadata;

namespace CMCS.Models
{
    public class Claim
    {
        [Key]
        // Primary Key for the Claim entity.
        public int ClaimId { get; set; }

        [Required]
        // Foreign Key linking the claim to the submitting Lecturer (User).
        public int LecturerId { get; set; }

        [Required]
        [Range(1, 12)]
        // The month (1-12) the hours were worked. Ensures data validity.
        public int MonthWorked { get; set; }

        [Required]
        [Range(2020, 2030)]
        // The year the hours were worked. Limited range to prevent future or overly old claims.
        public int YearWorked { get; set; }

        [Required]
        [Range(0.1, 500)]
        // The number of hours claimed. Must be positive and capped to a reasonable maximum.
        public decimal HoursWorked { get; set; }

        [Required]
        [Range(0, 10000)]
        // The hourly pay rate used for calculation. Capped at 10,000 for sanity checking.
        public decimal HourlyRate { get; set; }

        [Column(TypeName = "decimal(18,2)")]
        // The calculated total amount (HoursWorked * HourlyRate). Explicitly set database column type.
        public decimal TotalAmount { get; set; }

        [StringLength(500)]
        // Optional notes or justification from the lecturer regarding the claim.
        public string AdditionalNotes { get; set; }

        // The current status of the claim in the approval workflow. Defaults to PENDING.
        public ClaimStatus Status { get; set; } = ClaimStatus.PENDING;

        // Timestamp for when the claim was originally submitted. Defaults to current time.
        public DateTime SubmissionDate { get; set; } = DateTime.Now;

        // Timestamp for the last time any modification was made to the claim.
        public DateTime LastModifiedDate { get; set; } = DateTime.Now;

        // Flag to soft-delete or deactivate the claim without removing the record.
        public bool IsActive { get; set; } = true;

        [StringLength(100)]
        // The name or code of the module the lecturer taught.
        public string ModuleTaught { get; set; }

        [StringLength(20)]
        // A unique, human-readable reference code for the claim (e.g., CLM-2025-0001).
        public string ClaimReference { get; set; }

        // Navigation properties
        [ForeignKey("LecturerId")]
        // Navigation property to the User who submitted the claim.
        public virtual User Lecturer { get; set; }

        // Collection of documents (e.g., timesheets) supporting this claim. One-to-Many relationship.
        public virtual ICollection<Document> Documents { get; set; }

        // Collection of approval records from various approvers (PC, AM, HR). One-to-Many relationship.
        public virtual ICollection<ClaimApproval> Approvals { get; set; }
    }
}


