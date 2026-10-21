# PSScriptAnalyzer settings for iG Windows Tuner (picked up automatically when analyzing this folder).
# Every exclusion is a deliberate, documented decision (see docs/TESTING.md):
@{
    Severity     = @('Error', 'Warning', 'Information')
    ExcludeRules = @(
        # Every action type implements the same signature (Action, Context, Mode, Snapshot) so the
        # engine can dispatch uniformly; implementations that do not need a parameter still accept it.
        'PSReviewUnusedParameter',
        # A handful of internal functions intentionally return collections and are named for it
        # (Get-IgwtPowerSchemes, Get-IgwtInstalledGames, Get-IgwtRejectedTweaks, ...).
        'PSUseSingularNouns',
        # Informational: functions return PSCustomObjects/hashtables shaped by the JSON catalog.
        'PSUseOutputTypeCorrectly'
    )
}