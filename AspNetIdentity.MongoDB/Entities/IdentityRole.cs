namespace AspNetIdentity.MongoDB.Entities
{
    public class IdentityRole : Microsoft.AspNetCore.Identity.IdentityRole
    {
		public IdentityRole() { }

		public IdentityRole(string name) {
			Name = name;
			NormalizedName = name.ToUpperInvariant ();
		}

		public override string ToString () {
			return Name;
		}
	}
}