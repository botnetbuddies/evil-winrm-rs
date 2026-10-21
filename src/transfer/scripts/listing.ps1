param([string]$Path, [bool]$Wildcard)
if ($Wildcard) {
    $root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath((Split-Path $Path -Parent))
    $items = @(Get-ChildItem -Path $Path -Recurse -Force -ErrorAction Stop)
} else {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        $root = $item.FullName
        $items = @($item) + @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop)
    } else {
        $root = $item.DirectoryName
        $items = @($item)
    }
}
$result = @($items | ForEach-Object {
    [pscustomobject]@{
        path = $_.FullName
        relative = if ($_.FullName -eq $root) { '' } else { $_.FullName.Substring($root.TrimEnd('\').Length + 1) }
        directory = [bool]$_.PSIsContainer
    }
})
ConvertTo-Json -InputObject $result -Compress
