namespace AspNetIdentity.MongoDB.Entities
{
    public class TwoFactorRecoveryCode {
		public string Code { get; set; }

		public bool Redeemed { get; set; }
	}
}