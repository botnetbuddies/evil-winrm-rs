begin {
    __SETTINGS__
    $global:__STREAM__ = [IO.File]::Open($ewrStagingPath, $ewrMode)
    if ($global:__STREAM__.Length -ne $ewrOffset) { throw 'upload staging changed' }
    [void]$global:__STREAM__.Seek($ewrOffset, [IO.SeekOrigin]::Begin)
}
process {
    if (!$ewrCompressed) {
        $global:__STREAM__.Write($_, 0, $_.Length)
    } else {
        $memory = New-Object IO.MemoryStream(,$_)
        $gzip = New-Object IO.Compression.GZipStream($memory, [IO.Compression.CompressionMode]::Decompress)
        try {
            $buffer = New-Object byte[] 65536
            while (($count = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
                if ($global:__STREAM__.Length + $count -gt $ewrExpectedLength) { throw 'decompressed upload exceeds expected length' }
                $global:__STREAM__.Write($buffer, 0, $count)
            }
        } finally { $gzip.Dispose(); $memory.Dispose() }
    }
}
end {
    $global:__STREAM__.Dispose()
    Remove-Variable -Name __STREAM__ -Scope Global
    (Get-FileHash -LiteralPath $ewrStagingPath -Algorithm MD5 -ErrorAction Stop).Hash
}
