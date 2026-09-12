namespace OneShot.Web.Secrets;

internal interface ISweepableSecretStore
{
    int SweepExpired(int maxScan);
}
