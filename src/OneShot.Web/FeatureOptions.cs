namespace OneShot.Web;

// Issue #77's split-channel key delivery is entirely client-side and opt-in per secret already, but an
// operator may still want to turn the option off deployment-wide (e.g. to keep a single, simpler flow, or a
// policy against manual key transcription) rather than leave every user free to choose it. Configuration,
// not code: `Features:SplitKeyDelivery` / `Features__SplitKeyDelivery`.
internal sealed class FeatureOptions
{
    public bool SplitKeyDelivery { get; init; } = true;
}
