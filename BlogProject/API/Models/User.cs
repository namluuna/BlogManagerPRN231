using System;
using System.Collections.Generic;

namespace API.Models
{
    public partial class User
    {
        public User()
        {
            Comments = new HashSet<Comment>();
            FavoritePosts = new HashSet<FavoritePost>();
            Likes = new HashSet<Like>();
            Notifications = new HashSet<Notification>();
            Posts = new HashSet<Post>();
            Reports = new HashSet<Report>();
        }

        public int Id { get; set; }
        public string Username { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string PasswordHash { get; set; } = null!;
        public string Role { get; set; } = null!;
        public DateTime? CreatedAt { get; set; }

        public virtual ICollection<Comment> Comments { get; set; }
        public virtual ICollection<FavoritePost> FavoritePosts { get; set; }
        public virtual ICollection<Like> Likes { get; set; }
        public virtual ICollection<Notification> Notifications { get; set; }
        public virtual ICollection<Post> Posts { get; set; }
        public virtual ICollection<Report> Reports { get; set; }
    }
}
