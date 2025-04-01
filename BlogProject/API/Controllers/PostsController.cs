
using API.Data;
using API.DTO;
﻿using API.Infrastructure;
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
        public async Task<IActionResult> CreatePost([FromBody] PostDto postDto)
        {
            if (postDto == null)
            {
                return BadRequest("No data received.");
            }
            if (string.IsNullOrEmpty(postDto.Title) || string.IsNullOrEmpty(postDto.Content))
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
                Title = postDto.Title,
                Content = postDto.Content,
                AuthorId = userId,
                UpdatedAt = DateTime.UtcNow
            };
            _context.Posts.Add(post);
            _context.SaveChanges();

            return Ok(post);
        }
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdatePost(int id, [FromBody] PostDto postDto)
        {
            var existingPost = await _context.Posts.FindAsync(id);
            if (existingPost == null)
            {
                return NotFound();
            }

            existingPost.Title = postDto.Title;
            existingPost.Content = postDto.Content;
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
        [HttpGet("{id}")]
        public async Task<IActionResult> GetPostsById(int id)
        {
            var post = await _context.Posts.FirstOrDefaultAsync(p => p.Id == id);

            return Ok(post);
        }
        [HttpGet("search/{TitleOrContent}")]
        public async Task<IActionResult> SearchPostsByTitle(string TitleOrContent)
        {
            if (string.IsNullOrEmpty(TitleOrContent))
            {
                return BadRequest("Search string cannot be empty.");
            }

            var posts = await _context.Posts
                                       .Where(p => p.Title.Contains(TitleOrContent) || p.Content.Contains(TitleOrContent))
                                       .ToListAsync();

            return Ok(posts);
        }
        
    }
}
