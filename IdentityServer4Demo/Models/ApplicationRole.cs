using AspNetIdentity.MongoDB.Entities;

namespace IdentityServer4Demo.Models {
    public class ApplicationRole : IdentityRole {
        public ApplicationRole (string roleName) : base (roleName) {

        }
    }
}