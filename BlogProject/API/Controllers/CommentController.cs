using API.Data;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CommentController : ControllerBase
    {
        private readonly BlogManagementContext _context;
        public CommentController(BlogManagementContext context)
        {
            _context = context;
        }

    }
}
