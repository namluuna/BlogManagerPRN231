using System;
using System.Collections.Generic;

namespace API.Models
{
    public partial class FavoritePost
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public int PostId { get; set; }
        public DateTime? CreatedAt { get; set; }
    }
}
