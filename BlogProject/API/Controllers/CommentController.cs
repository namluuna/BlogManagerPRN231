using API.Data;
using API.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommentController : ControllerBase
    {
        private readonly Data.BlogManagementContext _context;
        public CommentController(Data.BlogManagementContext context)
        {
            _context = context;
        }
        [HttpGet("comment/{postId}")]
        public IActionResult GetCommentInPost(int postId) 
        {
            var data = _context.Posts
                .Where(c => c.Id == postId)
                .Include(c => c.Comments)
                .ThenInclude(c => c.User)
                .Select(c => new
                {
                    PostId = c.Id,
                    PostTitle = c.Title,
                    Content = c.Content,
                    Comments = c.Comments.Select(s => new
                    {
                        s.Id,
                        CommentDate = s.CreatedAt.HasValue ? s.CreatedAt.Value.ToString("dd/MM/yyyy") : "N/A",
                        s.Content,
                        Author = new
                        {
                            s.User.Id,
                            s.User.Username
                        }
                    }).ToList()
                })
                .FirstOrDefault();

            return Ok(data);

        }
        [HttpPost("comment/{postId}/{userId}/{content}")]
        public IActionResult CommentToPost(int postId, int userId, string content) 
        {
            if (string.IsNullOrEmpty(content))
            {
                return BadRequest("Comment must not empty");
            }
            var data = _context.Posts.Find(postId);
            if (data == null) 
            { 
                return NotFound("Post not exist");
            }
            var user = _context.Users.Find(userId);
            if (user == null)
            {
                return NotFound("User not exist");
            }
            var newComment = new Comment
            {
                Content = content,
                CreatedAt = DateTime.UtcNow,
                PostId = postId,
                UserId = userId,
            };
            _context.Comments.Add(newComment);
            _context.SaveChanges();
            return Ok(new
            {
                Message = "Add comment!",
                Comment = new
                {
                    newComment.Id,
                    newComment.Content,
                    CommentDate = newComment.CreatedAt.HasValue ? newComment.CreatedAt.Value.ToString("dd/MM/yyyy") : "N/A",
                    Author = new
                    {
                        user.Id,
                        user.Username
                    }
                }
            });
        }
        [HttpDelete("comment/{commentId}")]
        public IActionResult DeleteComment(int commentId) 
        { 
            var checkExistReport = _context.Reports.FirstOrDefault(report => report.CommentId == commentId);
            if(checkExistReport != null)
            {
                return NotFound("Cannot Delete when a report exist");
            }
            var comment = _context.Comments.Find(commentId);
            if (comment == null)
            {
                return NotFound("Comment not exists.");
            }

            _context.Comments.Remove(comment);
            _context.SaveChanges();
            return Ok(new
            {
                Message = "Deleted!",
                DeletedCommentId = commentId
            });
        }
        [HttpPut("comment/{postId}/{commentId}/{userId}/{content}")]
        public IActionResult PutComment(int postId, int commentId,int userId, string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return BadRequest("Comment must not empty");
            }
            var data = _context.Posts.Find(postId);
            if (data == null)
            {
                return NotFound("Post not exist");
            }
            var user = _context.Users.Find(userId);
            if (user == null)
            {
                return NotFound("User not exist");
            }
            var comment = _context.Comments.FirstOrDefault(c => c.Id == commentId && c.PostId == postId && c.UserId == userId);
            if (comment == null)
            {
                return NotFound("Comment not exist or belongs to this user");
            }
            comment.Content = content;
            comment.CreatedAt = DateTime.UtcNow;
            _context.SaveChanges();
            return Ok(new
            {
                Message = "Updated Comment",
                UpdatedComment = new
                {
                    comment.Id,
                    comment.Content,
                    UpdatedDate = comment.CreatedAt.HasValue ? comment.CreatedAt.Value.ToString("dd/MM/yyyy") : "N/A",
                    Author = new
                    {
                        user.Id,
                        user.Username
                    }
                }
            });
        }
    }
}
