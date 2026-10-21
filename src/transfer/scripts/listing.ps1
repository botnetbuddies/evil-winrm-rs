param([string]$Path, [bool]$Wildcard)
if ($Wildcard) {
    $parent = Split-Path $Path -Parent
    if ([string]::IsNullOrEmpty($parent)) { $parent = '.' }
    $root = (Get-Item -LiteralPath $parent -Force -ErrorAction Stop).FullName
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
