param([string]$Path)
@{
    size = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length
    md5 = (Get-FileHash -LiteralPath $Path -Algorithm MD5 -ErrorAction Stop).Hash
} | ConvertTo-Json -Compress
