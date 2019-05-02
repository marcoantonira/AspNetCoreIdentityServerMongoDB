using AspNetIdentity.MongoDB.Entities;
using AspNetIdentity.MongoDB.Interfaces;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using IdentityRole = AspNetIdentity.MongoDB.Entities.IdentityRole;
using IdentityUser = AspNetIdentity.MongoDB.Entities.IdentityUser;

namespace AspNetIdentity.MongoDB.Stores
{
    public class UserStore<TUser, TRole>:
		IUserClaimStore<TUser>,
		IUserLoginStore<TUser>,
		IUserRoleStore<TUser>,
		IUserPasswordStore<TUser>,
		IUserSecurityStampStore<TUser>,
		IUserEmailStore<TUser>,
		IUserPhoneNumberStore<TUser>,
		IQueryableUserStore<TUser>,
		IUserTwoFactorStore<TUser>,
		IUserLockoutStore<TUser>,
		IUserAuthenticatorKeyStore<TUser>,
		IUserAuthenticationTokenStore<TUser>,
		IUserTwoFactorRecoveryCodeStore<TUser> where TUser : IdentityUser where TRole : IdentityRole {

		private readonly IIdentityDbContext<TUser, TRole> _context;
        private readonly ILookupNormalizer _normalizer;

        private IQueryable<TRole> _roles => this._context.Roles.AsQueryable();

        public UserStore (IIdentityDbContext<TUser, TRole> context, ILookupNormalizer normalizer) {

            _context = context ?? throw new ArgumentNullException (nameof (context));
            _normalizer = normalizer;
        }

        public IQueryable<TUser> Users => this._context.Users.AsQueryable();

        public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user.Claims == null) user.Claims = new List<IdentityUserClaim<string>>();

            user.Claims.AddRange(claims.Select(claim => new IdentityUserClaim<string>()
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            }));
            
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user.Logins == null) user.Logins = new List<IdentityUserLogin<string>>();

            user.Logins.Add(new IdentityUserLogin<string>
            {
                UserId = user.Id,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName,
                ProviderKey = login.ProviderKey
            });

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            if (user.Roles == null) user.Roles = new List<string>();
            user.Roles.Add(roleName);

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));

            return await Task.FromResult(found?.RecoveryCodes.Count ?? 0);
        }

        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.UserName.Equals(user.UserName));
            if (found != null) return IdentityResult.Failed(new IdentityError { Code = "Username already in use" });

            await this._context.Users.InsertOneAsync(user);

            if (user.Email != null)
            {
                await SetEmailAsync(user, user.Email, cancellationToken);
            }

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            await this._context.Users.DeleteOneAsync(x => x.Id == user.Id);
            return IdentityResult.Success;
        }

        public void Dispose()
        {
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.NormalizedEmail.Equals(normalizedEmail)));
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(userId)));
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey)));
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.NormalizedUserName.Equals(normalizedUserName)));
        }

        public async Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.AccessFailedCount ?? user.AccessFailedCount);
        }

        public async Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.AuthenticatorKey ?? user.AuthenticatorKey);
        }

        public async Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));
            return await Task.FromResult(found?.Claims?.Select(x => new Claim(x.ClaimType, x.ClaimValue))?.ToList() ?? new List<Claim>());
        }

        public async Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.Email ?? user.Email);
        }

        public async Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            
            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.EmailConfirmed ?? user.EmailConfirmed);
        }

        public async Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.LockoutEnabled ?? user.LockoutEnabled);
        }

        public async Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.LockoutEnd ?? user.LockoutEnd);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));
            return await Task.FromResult(found?.Logins?.Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName))?.ToList() ?? new List<UserLoginInfo>());
        }

        public async Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.NormalizedEmail ?? user.NormalizedEmail);
        }

        public async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.NormalizedUserName ?? user.NormalizedUserName);
        }

        public async Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(user.PasswordHash);
        }

        public async Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.PhoneNumber ?? user.PhoneNumber);
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.PhoneNumberConfirmed ?? user.PhoneNumberConfirmed);
        }

        public async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult((this.Users.FirstOrDefault(x => x.Id.Equals(user.Id)))?.Roles?.Select(roleId => this._roles.FirstOrDefault(x => x.Id.Equals(roleId))).Where(x => x != null).Select(x => x.Name).ToList() ?? new List<string>());
        }

        public async Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(user.SecurityStamp);
        }

        public async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(user?.Tokens?.FirstOrDefault(x => x.LoginProvider == loginProvider && x.Name == name)?.Value);
        }

        public async Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.TwoFactorEnabled ?? user.TwoFactorEnabled);
        }

        public async Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(user?.Id);
        }

        public async Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(user.UserName);
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.Where(x => x.Claims.Any(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value)).ToList());
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.Where(x => x.Roles.Any(r => r.Equals(roleName))).ToList());
        }

        public async Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return await Task.FromResult(this.Users.FirstOrDefault(x => x.Id.Equals(user.Id))?.PasswordHash != null);
        }

        public async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.AccessFailedCount++;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
            return user.AccessFailedCount;
        }

        public async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));
            return await Task.FromResult(found?.Roles.Contains(roleName) ?? false);
        }

        public async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));
            if (found == null) return false;

            var c = user.RecoveryCodes.FirstOrDefault(x => x.Code == code);

            if (c == null || c.Redeemed) return false;

            c.Redeemed = true;

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);

            return true;
        }

        public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            foreach (var claim in claims)
            {
                user?.Claims?.RemoveAll(x => x.ClaimType == claim.Type);
            }

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.Roles.Remove(roleName);

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TUser found = this.Users.FirstOrDefault(x => x.Id.Equals(user.Id));
            user.Logins.RemoveAll(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey);
            found.Logins.RemoveAll(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey);
            
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user?.Tokens == null) return;

            user.Tokens.RemoveAll(x => x.LoginProvider == loginProvider && x.Name == name);
            
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user?.Claims?.RemoveAll(x => x.ClaimType == claim.Type);

            user?.Claims?.Add(new IdentityUserClaim<string>()
            {
                ClaimType = newClaim.Type,
                ClaimValue = newClaim.Value
            });

            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.RecoveryCodes = recoveryCodes.Select(x => new TwoFactorRecoveryCode { Code = x, Redeemed = false })
                .ToList();
            
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.AccessFailedCount = 0;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.AuthenticatorKey = key;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await SetNormalizedEmailAsync(user, user.Email, cancellationToken);/////////////
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.LockoutEnabled = enabled;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.LockoutEnd = lockoutEnd;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.NormalizedEmail = normalizedEmail;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.PasswordHash = passwordHash;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.PhoneNumber = phoneNumber;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.PhoneNumberConfirmed = confirmed;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.SecurityStamp = stamp;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (user.Tokens == null) user.Tokens = new List<IdentityUserToken<string>>();

            var token = user.Tokens.FirstOrDefault(x => x.LoginProvider == loginProvider && x.Name == name);

            if (token == null)
            {
                token = new IdentityUserToken<string> { LoginProvider = loginProvider, Name = name, Value = value };
                user.Tokens.Add(token);
            }
            else
            {
                token.Value = value;
            }
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.TwoFactorEnabled = enabled;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.UserName = userName;
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await SetEmailAsync(user, user.Email, cancellationToken);
            await this._context.Users.ReplaceOneAsync(x => x.Id == user.Id, user);
            return IdentityResult.Success;
        }
    }
}