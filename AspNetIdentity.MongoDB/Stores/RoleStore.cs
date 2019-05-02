using AspNetIdentity.MongoDB.Entities;
using AspNetIdentity.MongoDB.Interfaces;
using MongoDB.Driver;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetIdentity.MongoDB.Stores
{
    public class RoleStore<TRole> : Microsoft.AspNetCore.Identity.IQueryableRoleStore<TRole> where TRole : IdentityRole
    {

        private readonly IIdentityDbContext<TRole> _context;

        public RoleStore(IIdentityDbContext<TRole> context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public IQueryable<TRole> Roles => this._context.Roles.AsQueryable();

        public async Task<Microsoft.AspNetCore.Identity.IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            TRole found = this.Roles.FirstOrDefault(x => x.NormalizedName.Equals(role.NormalizedName));
            if (found == null) await this._context.Roles.InsertOneAsync(role);
            return Microsoft.AspNetCore.Identity.IdentityResult.Success;
        }

        public async Task<Microsoft.AspNetCore.Identity.IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            await _context.Roles.DeleteOneAsync(x => x.Id == role.Id);
            return Microsoft.AspNetCore.Identity.IdentityResult.Success;
        }

        public void Dispose()
        {
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            return await Task.FromResult(this.Roles.FirstOrDefault(x => x.Id.Equals(roleId)));
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            return await Task.FromResult(this.Roles.FirstOrDefault(x => x.NormalizedName.Equals(normalizedRoleName)));
        }

        public async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return await Task.FromResult(role.NormalizedName);
        }

        public async Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            return await Task.FromResult(role.Id);
        }

        public async Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            return await Task.FromResult(role.Name);
        }

        public async Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken)
        {
            role.NormalizedName = normalizedName;
            await this._context.Roles.ReplaceOneAsync(x => x.Id == role.Id, role);
        }

        public async  Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            role.Name = roleName;
            await this._context.Roles.ReplaceOneAsync(x => x.Id == role.Id, role);
        }

        public async Task<Microsoft.AspNetCore.Identity.IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            await this._context.Roles.ReplaceOneAsync(x => x.Id == role.Id, role);
            return Microsoft.AspNetCore.Identity.IdentityResult.Success;
        }
    }
}