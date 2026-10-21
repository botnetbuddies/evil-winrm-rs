param([string]$Payload, [bool]$CloseSend)
try {
    $state = $global:__SOCKET__
    $socket = $state.client
    # Retain the NetworkStream across a send-side shutdown: .NET Framework's
    # TcpClient.GetStream() rejects a socket after Shutdown(Send).
    $stream = $state.stream
    if ($Payload.Length -gt 0) {
        $bytes = [Convert]::FromBase64String($Payload)
        $task = $stream.WriteAsync($bytes, 0, $bytes.Length)
        if (!$task.Wait(10000)) { throw 'TCP write timed out' }
    }
    if ($CloseSend) { $socket.Client.Shutdown([Net.Sockets.SocketShutdown]::Send) }
    $buffer = New-Object byte[] ([Math]::Min($socket.Available, 65536))
    $count = 0
    if ($buffer.Length -gt 0) { $count = $stream.Read($buffer, 0, $buffer.Length) }
    @{
        data = [Convert]::ToBase64String($buffer, 0, $count)
        closed = [bool]($socket.Client.Poll(0, [Net.Sockets.SelectMode]::SelectRead) -and $socket.Available -eq 0 -and $count -eq 0)
    } | ConvertTo-Json -Compress
} catch {
    Write-Output ($_ | Out-String)
    throw
}
