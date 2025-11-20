using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CMCS.Models
{
    public class Document
    {
        [Key]
        public int DocumentId { get; set; }

        [Required]
        public int ClaimId { get; set; }

        [Required]
        [StringLength(255)]
        public string FileName { get; set; }

        [Required]
        [StringLength(500)]
        public string FilePath { get; set; }

        [StringLength(10)]
        public string FileType { get; set; }

        public long FileSize { get; set; }

        public DateTime UploadDate { get; set; } = DateTime.Now;

        [StringLength(200)]
        public string Description { get; set; }

        public bool IsVerified { get; set; } = false;

        [StringLength(100)]
        public string ContentType { get; set; }

        // Navigation properties
        [ForeignKey("ClaimId")]
        public virtual Claim Claim { get; set; }
    }
}
