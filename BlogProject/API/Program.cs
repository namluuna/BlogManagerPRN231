using System.Security.Authentication;
using API.Data;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace API;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = CreateHostBuilder(args);

        var app = builder.Build();

        app.Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.ConfigureKestrel(serverOptions =>
                {
                    serverOptions.Limits.MinRequestBodyDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
                    serverOptions.Limits.MinResponseDataRate = new MinDataRate(100, TimeSpan.FromSeconds(10));
                    serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(2);
                    serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(1);
                    serverOptions.ConfigureHttpsDefaults(listenOptions =>
                    {
                        listenOptions.SslProtocols = SslProtocols.Tls12;
                    });
                })
                    .ConfigureServices((context, services) =>
                    {
                        // Lấy cấu hình từ appsettings.json
                        var configuration = context.Configuration;

                        // Thêm DbContext
                        services.AddDbContext<BlogManagementContext>(options =>
                            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
                    })
                    .UseStartup<Startup>();
            });
}
