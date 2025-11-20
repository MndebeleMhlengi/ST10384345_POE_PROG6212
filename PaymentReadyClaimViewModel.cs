namespace CMCS.Models.ViewModels
{
    public class PaymentReadyClaimViewModel
    {
        public int Id { get; set; }
        public string LecturerName { get; set; }
        public string LecturerInitials { get; set; }
        public string EmployeeNumber { get; set; }
        public string ClaimReference { get; set; }
        public string MonthYear { get; set; }
        public int HoursWorked { get; set; }
        public decimal TotalAmount { get; set; }
        public DateTime FinalApprovalDate { get; set; }
        public string ApprovedBy { get; set; }
    }
}