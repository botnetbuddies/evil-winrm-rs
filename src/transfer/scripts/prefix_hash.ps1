param([string]$Path, [long]$Length)
$file = [IO.File]::OpenRead($Path)
$hash = [Security.Cryptography.MD5]::Create()
try {
    $left = $Length
    $buffer = New-Object byte[] 65536
    while ($left -gt 0) {
        $read = $file.Read($buffer, 0, [int][Math]::Min($left, $buffer.Length))
        if (!$read) { throw 'source shortened' }
        [void]$hash.TransformBlock($buffer, 0, $read, $buffer, 0)
        $left -= $read
    }
    [void]$hash.TransformFinalBlock([byte[]]@(), 0, 0)
    [BitConverter]::ToString($hash.Hash).Replace('-', '')
} finally { $file.Dispose(); $hash.Dispose() }
