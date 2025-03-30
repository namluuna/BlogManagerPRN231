
using API.Data;
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
        private readonly BlogManagementContext _context;
        public PostsController(BlogManagementContext context)
        {
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> CreatePost(string title, string content)
        {
            if (string.IsNullOrEmpty(title) || string.IsNullOrEmpty(content))
            {
                return BadRequest("Title and Content are required.");
            }
            var userName = User.Identity?.Name!;
            if (string.IsNullOrEmpty(userName))
            {
                return Unauthorized("User not authenticated.");
            }
            var userId = _context.Users.FirstOrDefault(u => u.Username == userName).Id;
            Post post = new Post
            {
                Title = title,
                Content = content,
                AuthorId = userId,
                UpdatedAt = DateTime.UtcNow
            };
            _context.Posts.Add(post);
            await _context.SaveChangesAsync();

            return Ok(post);
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

            return Ok(existingPost);
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
        public async Task<IActionResult> SearchPostsByTitle(string title)
        {
            if (string.IsNullOrEmpty(title))
            {
                return BadRequest("Search string cannot be empty.");
            }

            var posts = await _context.Posts
                                       .Where(p => p.Title.Contains(title))
                                       .ToListAsync();

            return Ok(posts);
        }
        [HttpGet("search/content")]
        public async Task<IActionResult> SearchPostsByContent(string content)
        {
            if (string.IsNullOrEmpty(content))
            {
                return BadRequest("Search string cannot be empty.");
            }

            var posts = await _context.Posts
                          .Where(p => EF.Functions.Like(p.Content, $"%{content}%"))
                          .ToListAsync();

            return Ok(posts);
        }
    }
}
