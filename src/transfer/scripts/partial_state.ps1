param([string]$Path)
$state = if (Test-Path -LiteralPath $Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) { throw 'unsafe upload staging path' }
    @{ size = $item.Length; md5 = (Get-FileHash -LiteralPath $Path -Algorithm MD5 -ErrorAction Stop).Hash }
} else { @{ size = 0; md5 = '' } }
$state | ConvertTo-Json -Compress
