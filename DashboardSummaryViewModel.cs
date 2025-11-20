namespace CMCS.Models.ViewModels
{
    public class DashboardSummaryViewModel
    {
        public int ReadyForPayment { get; set; }
        public decimal TotalAmount { get; set; }
        public int PaidThisMonth { get; set; }
        public int ActiveLecturers { get; set; }
    }
}