using AspNetIdentity.MongoDB;
using AspNetIdentity.MongoDB.DbContexts;
using AspNetIdentity.MongoDB.Interfaces;
using AspNetIdentity.MongoDB.Stores;
using AspNetCore.MongoDB.Shared.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.IdGenerators;
using System;
using IdentityRole = AspNetIdentity.MongoDB.Entities.IdentityRole;
using IdentityUser = AspNetIdentity.MongoDB.Entities.IdentityUser;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class IdentityMongoDBBuilderExtensions
    {
        public static IServiceCollection AddMongoDBIdentity<TUser>(this IServiceCollection services) where TUser : IdentityUser
        {
            return services.AddMongoDBIdentity<TUser, IdentityRole>();
        }

        public static IServiceCollection AddMongoDBIdentity<TUser>(this IServiceCollection services, IConfiguration configuration) where TUser : IdentityUser
        {
            services.Configure<MongoDBConfiguration>(options => options = new MongoDBConfiguration {
                ConnectionString = configuration.GetSection("MongoDB::ConnectionString").Value
            });

            return services.AddMongoDBIdentity<TUser, IdentityRole>();
        }

        public static IServiceCollection AddMongoDBIdentity<TUser, TRole>(this IServiceCollection services, IConfiguration configuration) where TUser : IdentityUser where TRole : IdentityRole
        {
            services.Configure<MongoDBConfiguration>(options => options = new MongoDBConfiguration {
                ConnectionString = configuration.GetSection("MongoDB::ConnectionString").Value
            });

            return services.AddMongoDBIdentity<TUser, TRole>();
        }

        public static IServiceCollection AddMongoDBIdentity<TUser, TRole>(this IServiceCollection services) where TUser : IdentityUser where TRole : IdentityRole
        {
            //ConfigureIgnoreExtraElementsIdentity<TUser, TRole>();

            var builder = services.AddIdentity<TUser, TRole>();

            builder.AddRoleStore<RoleStore<TRole>>()
                .AddUserStore<UserStore<TUser, TRole>>()
                .AddUserManager<UserManager<TUser>>()
                .AddDefaultTokenProviders();

            builder.Services.AddScoped<IIdentityDbContext<TRole>, IdentityDbContext<TRole>>();
            builder.Services.AddScoped<IIdentityDbContext<TUser, TRole>, IdentityDbContext<TUser, TRole>>();

            builder.Services.AddTransient<IUserStore<TUser>, UserStore<TUser, TRole>>();
            builder.Services.AddTransient<IRoleStore<TRole>, RoleStore<TRole>>();
            
            return builder.Services;
        }

        private static void ConfigureIgnoreExtraElementsIdentity<TUser, TRole>() where TUser : IdentityUser where TRole : IdentityRole
        {
            BsonClassMap.RegisterClassMap<IdentityUser>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(c => c.Id).SetIdGenerator(GuidGenerator.Instance);
                cm.MapField(c => c.PasswordHash).SetIgnoreIfNull(true);
                cm.MapField(c => c.Roles).SetIgnoreIfNull(true);
                cm.MapField(c => c.Claims).SetIgnoreIfNull(true);
                cm.MapField(c => c.Logins).SetIgnoreIfNull(true);
                cm.MapField(c => c.Tokens).SetIgnoreIfNull(true);
                cm.MapField(c => c.RecoveryCodes).SetIgnoreIfNull(true);
            });

            BsonClassMap.RegisterClassMap<IdentityRole>(cm =>
            {
                cm.AutoMap();
                cm.MapIdMember(c => c.Id).SetIdGenerator(GuidGenerator.Instance);
            });
        }
    }
}
