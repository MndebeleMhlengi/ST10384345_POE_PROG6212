using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CMCS.Models
{
    public class ClaimApproval
    {
        [Key]
        public int ApprovalId { get; set; }

        [Required]
        public int ClaimId { get; set; }

        [Required]
        public int ApproverId { get; set; }

        [Required]
        public ApprovalLevel Level { get; set; }

        public ApprovalStatus Status { get; set; } = ApprovalStatus.PENDING;

        [StringLength(500)]
        public string Comments { get; set; }

        public DateTime ReviewDate { get; set; } = DateTime.Now;

        public DateTime? ApprovalDate { get; set; }

        public bool IsActive { get; set; } = true;

        [StringLength(200)]
        public string RejectionReason { get; set; }

        // Navigation properties
        [ForeignKey("ClaimId")]
        public virtual Claim Claim { get; set; }

        [ForeignKey("ApproverId")]
        public virtual User Approver { get; set; }
    }
}