namespace OneShot.Web.Security;

internal static class IdentityCookie
{
    // The only authentication type the audit logger trusts; the handler that issues it arrives with the whoami endpoint.
    public const string Scheme = "OneShot.IdentityCookie";
}
