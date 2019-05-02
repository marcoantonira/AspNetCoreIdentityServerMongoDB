// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using AspNetIdentity.MongoDB.Entities;
using AspNetIdentity.MongoDB.Interfaces;
using AspNetCore.MongoDB.Shared.Configuration;
using AspNetCore.MongoDB.Shared.DbContexts;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace AspNetIdentity.MongoDB.DbContexts
{
    public class IdentityDbContext<TUser, TRole> : IdentityDbContext<TRole>, IIdentityDbContext<TUser, TRole> where TUser : IdentityUser where TRole : IdentityRole
    {
        private readonly IMongoCollection<TUser> _users;

        public IdentityDbContext(IOptions<MongoDBConfiguration> settings)
            : base(settings)
        {
            _users = Database.GetCollection<TUser>(Constants.TableNames.IdentityUser);

            // CreateUserIndexes();
        }

        private void CreateUserIndexes()
        {
            var indexOptions = new CreateIndexOptions() { Background = true };

            var builder = Builders<TUser>.IndexKeys;
            var userIdIndexModel = new CreateIndexModel<TUser>(builder.Ascending(_ => _.Id), indexOptions);
            _users.Indexes.CreateOne(userIdIndexModel);
        }

        public IMongoCollection<TUser> Users
        {
            get { return _users; }
        }
    }

    public class IdentityDbContext<TRole> : MongoDBContextBase, IIdentityDbContext<TRole> where TRole : IdentityRole
    {
        private readonly IMongoCollection<TRole> _roles;

        public IdentityDbContext(IOptions<MongoDBConfiguration> settings)

            : base(settings)
        {
            _roles = Database.GetCollection<TRole>(Constants.TableNames.IdentityRole);
            
            // CreateRoleIndexes();
        }

        private void CreateRoleIndexes()
        {
            var indexOptions = new CreateIndexOptions() { Background = true };

            var builder = Builders<TRole>.IndexKeys;
            var roleIdIndexModel = new CreateIndexModel<TRole>(builder.Ascending(_ => _.Id), indexOptions);
            _roles.Indexes.CreateOne(roleIdIndexModel);
        }

        public IMongoCollection<TRole> Roles
        {
            get { return _roles; }
        }
    }
}