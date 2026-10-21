param([string]$Path, [long]$Offset, [int]$Count, [bool]$Compressed)
$file = [IO.File]::OpenRead($Path)
try {
    [void]$file.Seek($Offset, [IO.SeekOrigin]::Begin)
    $buffer = New-Object byte[] $Count
    $read = $file.Read($buffer, 0, $buffer.Length)
    if (!$Compressed) { [Convert]::ToBase64String($buffer, 0, $read) }
    else {
        $memory = New-Object IO.MemoryStream
        $gzip = New-Object IO.Compression.GZipStream($memory, [IO.Compression.CompressionLevel]::Fastest, $true)
        try { $gzip.Write($buffer, 0, $read) } finally { $gzip.Dispose() }
        try { [Convert]::ToBase64String($memory.ToArray()) } finally { $memory.Dispose() }
    }
} finally { $file.Dispose() }
