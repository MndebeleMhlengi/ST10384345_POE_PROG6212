using System.Collections.Generic;

namespace CMCS.Models.ViewModels
{
    public class HRDashboardViewModel
    {
        public int ReadyForPayment { get; set; }
        public decimal TotalAmount { get; set; }
        public int PaidThisMonth { get; set; }
        public int ActiveLecturers { get; set; }
        public IEnumerable<PaymentReadyClaimViewModel> Claims { get; set; }
    }
}