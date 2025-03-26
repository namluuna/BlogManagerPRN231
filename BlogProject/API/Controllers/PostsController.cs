using API.Infrastructure;
using API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class PostsController : ControllerBase
    {
        private readonly Data.BlogManagementContext _context;
        public PostsController(Data.BlogManagementContext context)
        {
            _context = context;
        }

        [HttpPost]
        public IActionResult CreatePost(string title, string content, int userId)
        {
            if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(content))
            {
                return BadRequest("Title and Content are required.");
            }
            var getUser = _context.Users.FirstOrDefault(u => u.Id == userId);
            if (getUser == null)
            {
                return Unauthorized("User not authenticated.");
            }
            var newPost = new Post
            {
                Title = title,
                Content = content,
                AuthorId = getUser.Id,
                CreatedAt = DateTime.UtcNow,
                Status = "Published",
                UpdatedAt = DateTime.UtcNow
            };
            _context.Posts.Add(newPost);
            _context.SaveChanges();

            return Ok();
        }
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdatePost(int id, string title, string content)
        {
            var existingPost = await _context.Posts.FindAsync(id);
            if (existingPost == null)
            {
                return NotFound();
            }

            existingPost.Title = title;
            existingPost.Content = content;
            existingPost.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return NoContent();
        }
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeletePost(int id)
        {
            var post = await _context.Posts.FindAsync(id);
            if (post == null)
            {
                return NotFound();
            }

            _context.Posts.Remove(post);
            await _context.SaveChangesAsync();

            return NoContent();
        }
        [HttpGet]
        public async Task<IActionResult> GetPosts([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
        {
            var posts = await _context.Posts
                                       .Skip((page - 1) * pageSize)
                                       .Take(pageSize)
                                       .ToListAsync();

            return Ok(posts);
        }
        [HttpGet("search/title")]
        public async Task<IActionResult> SearchPostsByTitle([FromQuery] string query)
        {
            if (string.IsNullOrEmpty(query))
            {
                return BadRequest("Search query cannot be empty.");
            }

            var posts = await _context.Posts
                                       .Where(p => p.Title.Contains(query))
                                       .ToListAsync();

            return Ok(posts);
        }
        [HttpGet("search/content")]
        public async Task<IActionResult> SearchPostsByContent([FromQuery] string query)
        {
            if (string.IsNullOrEmpty(query))
            {
                return BadRequest("Search query cannot be empty.");
            }

            var posts = await _context.Posts
                                       .Where(p => p.Content.Contains(query))
                                       .ToListAsync();

            return Ok(posts);
        }
    }
}
