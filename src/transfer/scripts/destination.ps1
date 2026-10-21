param([string]$Path, [string]$Filename)
if (Test-Path -LiteralPath $Path -PathType Container) { $Path = Join-Path $Path $Filename }
[IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
