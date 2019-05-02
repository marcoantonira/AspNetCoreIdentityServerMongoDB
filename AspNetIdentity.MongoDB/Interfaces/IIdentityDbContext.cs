using AspNetIdentity.MongoDB.Entities;
using MongoDB.Driver;
using System;

namespace AspNetIdentity.MongoDB.Interfaces
{
    public interface IIdentityDbContext<TUser, TRole>: IIdentityDbContext<TRole> where TUser : IdentityUser where TRole: IdentityRole
    {
        IMongoCollection<TUser> Users { get; }
    }


    public interface IIdentityDbContext<TRole> : IDisposable where TRole : IdentityRole
    {
        IMongoCollection<TRole> Roles { get; }
    }
}