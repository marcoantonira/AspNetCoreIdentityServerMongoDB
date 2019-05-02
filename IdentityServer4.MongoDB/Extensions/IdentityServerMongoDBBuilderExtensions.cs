// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityServer4.MongoDB;
using AspNetCore.MongoDB.Shared.Configuration;
using IdentityServer4.MongoDB.DbContexts;
using IdentityServer4.MongoDB.Entities;
using IdentityServer4.MongoDB.Interfaces;
using IdentityServer4.MongoDB.Options;
using IdentityServer4.MongoDB.Services;
using IdentityServer4.MongoDB.Stores;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using MongoDB.Bson.Serialization;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class IdentityServerMongoDBBuilderExtensions
    {
        public static IIdentityServerBuilder AddMongoDBConfigurationStore(this IIdentityServerBuilder builder, Action<MongoDBConfiguration> setupAction)
        {
            builder.Services.Configure(setupAction);

            return builder.AddMongoDBConfigurationStore();
        }

        public static IIdentityServerBuilder AddMongoDBConfigurationStore(this IIdentityServerBuilder builder, IConfiguration configuration)
        {
            builder.Services.Configure<MongoDBConfiguration>(configuration);

            return builder.AddMongoDBConfigurationStore();
        }

        public static IIdentityServerBuilder AddMongoDBOperationalStore(this IIdentityServerBuilder builder, Action<MongoDBConfiguration> setupAction, Action<TokenCleanupOptions> tokenCleanUpOptions = null)
        {
            builder.Services.Configure(setupAction);

            return builder.AddMongoDBOperationalStore(tokenCleanUpOptions);
        }

        public static IIdentityServerBuilder AddMongoDBOperationalStore(this IIdentityServerBuilder builder, IConfiguration configuration, Action<TokenCleanupOptions> tokenCleanUpOptions = null)
        {
            builder.Services.Configure<MongoDBConfiguration>(configuration);

            return builder.AddMongoDBOperationalStore(tokenCleanUpOptions);
        }

        public static IIdentityServerBuilder AddMongoDBConfigurationStore(this IIdentityServerBuilder builder)
        {
            ConfigureIgnoreExtraElementsConfigurationStore();

            builder.Services.AddScoped<IConfigurationDbContext, ConfigurationDbContext>();

            builder.Services.AddTransient<IClientStore, ClientStore>();
            builder.Services.AddTransient<IResourceStore, ResourceStore>();
            builder.Services.AddTransient<ICorsPolicyService, CorsPolicyService>();

            return builder;
        }

        public static IIdentityServerBuilder AddMongoDBOperationalStore(this IIdentityServerBuilder builder, Action<TokenCleanupOptions> tokenCleanUpOptions = null)
        {
            ConfigureIgnoreExtraElementsOperationalStore();

            builder.Services.AddScoped<IPersistedGrantDbContext, PersistedGrantDbContext>();

            builder.Services.AddTransient<IPersistedGrantStore, PersistedGrantStore>();

            var tokenCleanupOptions = new TokenCleanupOptions();
            tokenCleanUpOptions?.Invoke(tokenCleanupOptions);
            builder.Services.AddSingleton(tokenCleanupOptions);
            builder.Services.AddSingleton<TokenCleanup>();

            return builder;
        }

        public static IApplicationBuilder UseIdentityServerMongoDBTokenCleanup(this IApplicationBuilder app, IApplicationLifetime applicationLifetime)
        {
            var tokenCleanup = app.ApplicationServices.GetService<TokenCleanup>();
            if (tokenCleanup == null)
            {
                throw new InvalidOperationException("AddMongoDBOperationalStore must be called on the service collection.");
            }
            applicationLifetime.ApplicationStarted.Register(tokenCleanup.Start);
            applicationLifetime.ApplicationStopping.Register(tokenCleanup.Stop);

            return app;
        }

        private static void ConfigureIgnoreExtraElementsConfigurationStore()
        {
            BsonClassMap.RegisterClassMap<Client>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
            BsonClassMap.RegisterClassMap<IdentityResource>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
            BsonClassMap.RegisterClassMap<ApiResource>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
        }

        private static void ConfigureIgnoreExtraElementsOperationalStore()
        {
            BsonClassMap.RegisterClassMap<PersistedGrant>(cm =>
            {
                cm.AutoMap();
                cm.SetIgnoreExtraElements(true);
            });
        }
    }
}