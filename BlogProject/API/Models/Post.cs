using System;
using System.Collections.Generic;

namespace API.Models
{
    public partial class Post
    {
        public Post()
        {
            Comments = new HashSet<Comment>();
            FavoritePosts = new HashSet<FavoritePost>();
            Likes = new HashSet<Like>();
        }

        public int Id { get; set; }
        public int AuthorId { get; set; }
        public string Title { get; set; } = null!;
        public string Content { get; set; } = null!;
        public DateTime? CreatedAt { get; set; }
        public DateTime? UpdatedAt { get; set; }
        public string? Status { get; set; }

        public virtual User Author { get; set; } = null!;
        public virtual ICollection<Comment> Comments { get; set; }
        public virtual ICollection<FavoritePost> FavoritePosts { get; set; }
        public virtual ICollection<Like> Likes { get; set; }
    }
}
