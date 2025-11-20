namespace CMCS.Models.ViewModels
{
    public class ClaimReviewViewModel
    {
        public int Id { get; set; }
        public string LecturerName { get; set; }
        public string LecturerInitials { get; set; }
        public string LecturerEmail { get; set; }
        public string ClaimReference { get; set; }
        public string MonthYear { get; set; }
        public int HoursWorked { get; set; }
        public decimal TotalAmount { get; set; }
        public DateTime SubmissionDate { get; set; }
        public int DocumentCount { get; set; }
        public int DaysAgo { get; set; }
    }
}