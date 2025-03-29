using System;
using System.Collections.Generic;

namespace API.Models
{
    public partial class Report
    {
        public int Id { get; set; }
        public int CommentId { get; set; }
        public int? ReportedBy { get; set; }
        public string Reason { get; set; } = null!;
        public DateTime? CreatedAt { get; set; }
        public virtual Comment Comment { get; set; } = null!;
        public virtual User? ReportedByNavigation { get; set; }
    }
}
