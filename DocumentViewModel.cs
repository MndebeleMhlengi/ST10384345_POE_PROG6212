namespace CMCS.Models.ViewModels
{
    public class DocumentViewModel
    {
        public int Id { get; set; }
        public string FileName { get; set; }
        public string DocumentType { get; set; }
        public string ClaimReference { get; set; }
        public string FileExtension { get; set; }
        public string FileSizeFormatted { get; set; }
        public DateTime UploadDate { get; set; }
        public string Status { get; set; }
    }
}