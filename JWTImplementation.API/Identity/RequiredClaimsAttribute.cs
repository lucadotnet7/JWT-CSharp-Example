using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace JWTImplementation.API.Identity
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class RequiredClaimsAttribute : Attribute, IAuthorizationFilter
    {
        private readonly string _claimName;
        private readonly string _claimValue;

        public RequiredClaimsAttribute(string claimName, string claimValue)
        {
            _claimName = claimName;
            _claimValue = claimValue;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.HasClaim(_claimName, _claimValue))
                context.Result = new ForbidResult();
        }
    }
}
