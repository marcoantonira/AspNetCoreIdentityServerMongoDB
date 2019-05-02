﻿using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace AspNetIdentity.MongoDB.Entities
{
    public class IdentityUser : Microsoft.AspNetCore.Identity.IdentityUser
    {
		public IdentityUser() {
			Roles = new List<string> ();
			Claims = new List<IdentityUserClaim<string>> ();
			Logins = new List<IdentityUserLogin<string>> ();
			Tokens = new List<IdentityUserToken<string>> ();
			RecoveryCodes = new List<TwoFactorRecoveryCode> ();
		}

		public string AuthenticatorKey { get; set; }

		public List<string> Roles { get; set; }

		public List<IdentityUserClaim<string>> Claims { get; set; }

		public List<IdentityUserLogin<string>> Logins { get; set; }

		public List<IdentityUserToken<string>> Tokens { get; set; }

		public List<TwoFactorRecoveryCode> RecoveryCodes { get; set; }
	}
}