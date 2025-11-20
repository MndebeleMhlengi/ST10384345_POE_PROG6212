using System.ComponentModel.DataAnnotations;

namespace CMCS.Models.ViewModels
{
    public class CreateClaimViewModel
    {
        [Required(ErrorMessage = "Please select a month.")]
        [Range(1, 12, ErrorMessage = "Invalid month selected.")]
        public int Month { get; set; }

        [Required(ErrorMessage = "Please select a year.")]
        [Range(2023, 2025, ErrorMessage = "Please select a valid year.")]
        public int Year { get; set; }

        [Required(ErrorMessage = "Hours worked is required.")]
        [Range(0.1, 500, ErrorMessage = "Hours worked must be between 0.1 and 500.")]
        [Display(Name = "Hours Worked")]
        public decimal HoursWorked { get; set; }

        [Required(ErrorMessage = "Hourly rate is required.")]
        [Range(0.01, 10000, ErrorMessage = "Hourly rate must be between R0.01 and R10000.")]
        [Display(Name = "Hourly Rate")]
        public decimal HourlyRate { get; set; }

        [Display(Name = "Module Taught")]
        [StringLength(100, ErrorMessage = "Module Taught cannot exceed 100 characters.")]
        public string? ModuleTaught { get; set; }

        [Display(Name = "Additional Notes")]
        [StringLength(500, ErrorMessage = "Additional Notes cannot exceed 500 characters.")]
        public string? AdditionalNotes { get; set; }
    }
}