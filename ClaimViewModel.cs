namespace CMCS.Models.ViewModels
{
    public class ClaimViewModel
    {
        public int Id { get; set; }
        public string ClaimReference { get; set; }
        public string MonthYear { get; set; }
        public string ModuleTaught { get; set; }
        public int HoursWorked { get; set; }
        public decimal HourlyRate { get; set; }
        public decimal TotalAmount { get; set; }
        public string Status { get; set; }
        public DateTime SubmissionDate { get; set; }
    }
}