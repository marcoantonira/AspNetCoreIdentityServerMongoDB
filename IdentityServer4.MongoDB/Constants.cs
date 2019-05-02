// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


namespace IdentityServer4.MongoDB
{
    public class Constants
    {
        public class TableNames
        {
            // Configuration
            public const string IdentityResource = "identityResources";
            public const string IdentityClaim = "identityClaims";

            public const string ApiResource = "apiResources";
            public const string ApiSecret = "apiSecrets";
            public const string ApiScope = "apiScopes";
            public const string ApiClaim = "apiClaims";
            public const string ApiScopeClaim = "apiScopeClaims";
            
            public const string Client = "clients";
            public const string ClientGrantType = "clientGrantTypes";
            public const string ClientRedirectUri = "clientRedirectUris";
            public const string ClientPostLogoutRedirectUri = "clientPostLogoutRedirectUris";
            public const string ClientScopes = "clientScopes";
            public const string ClientSecret = "clientSecrets";
            public const string ClientClaim = "clientClaims";
            public const string ClientIdPRestriction = "clientIdPRestrictions";
            public const string ClientCorsOrigin = "clientCorsOrigins";

            // Operational
            public const string PersistedGrant = "persistedGrants";
        }
    }
}