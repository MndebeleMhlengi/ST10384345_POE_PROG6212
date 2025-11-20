// ClaimSubmissionViewModel.cs
using System.ComponentModel.DataAnnotations;

namespace CMCS.Models.ViewModels
{
    public class ClaimSubmissionViewModel
    {
        [Required(ErrorMessage = "Month worked is required")]
        [Range(1, 12, ErrorMessage = "Please select a valid month")]
        [Display(Name = "Month Worked")]
        public int MonthWorked { get; set; }

        [Required(ErrorMessage = "Year worked is required")]
        [Range(2020, 2030, ErrorMessage = "Please enter a valid year")]
        [Display(Name = "Year Worked")]
        public int YearWorked { get; set; }

        [Required(ErrorMessage = "Hours worked is required")]
        // Changed to decimal for HoursWorked for better consistency with HourlyRate/TotalAmount
        [Range(0.1, 500.0, ErrorMessage = "Hours must be between 0.1 and 500")] 
        [Display(Name = "Hours Worked")]
        public decimal HoursWorked { get; set; }

        [Required(ErrorMessage = "Hourly rate is required")]
        // Changed Range minimum to 0.01 to enforce greater than 0, matching the first snippet's logic
        [Range(0.01, 10000.0, ErrorMessage = "Hourly rate must be greater than 0")]
        [Display(Name = "Hourly Rate (R)")] // Updated display name for clarity
        public decimal HourlyRate { get; set; }

        [Required(ErrorMessage = "Module taught is required")]
        [StringLength(100, ErrorMessage = "Module name cannot exceed 100 characters")]
        [Display(Name = "Module Taught")]
        public string ModuleTaught { get; set; }

        [StringLength(500, ErrorMessage = "Additional notes cannot exceed 500 characters")]
        [Display(Name = "Additional Notes")]
        public string AdditionalNotes { get; set; }

        [Display(Name = "Total Amount")]
        // Read-only property to calculate the total claim amount
        public decimal TotalAmount => HoursWorked * HourlyRate; 
    }
}