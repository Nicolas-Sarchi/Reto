using Dominio.Interfaces;
using Aplicacion.UnitOfWork;
using Aplicacion.Repository;
using Persistencia.Data;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Mvc;
using API.Services;
using Microsoft.AspNetCore.Identity;
using Dominio.Entities;
using Microsoft.AspNetCore.Authorization;

namespace APIIncidencias.Extensions;

public static class ApplicationServiceExtension
{
    public static void ConfigureCors(this IServiceCollection services) =>
        services.AddCors(options =>
        {
            options.AddPolicy(
                "CorsPolicy",
                builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()
            );
        });

    public static void AddAppServices(this IServiceCollection services)
    {
        services.AddScoped<IUnitOfWork, Unitofwork>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<IPasswordHasher<User>, PasswordHasher<User>>();
        services.AddScoped<IAuthorizationHandler, GlobalVerbRoleHandler>();
    }
}