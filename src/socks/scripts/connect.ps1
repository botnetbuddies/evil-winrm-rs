param([string]$TargetHost, [int]$TargetPort)
$client = New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetworkV6)
$client.Client.DualMode = $true
try {
    $task = $client.ConnectAsync($TargetHost, $TargetPort)
    if (!$task.Wait(10000)) { throw 'TCP connect timed out' }
    $client.NoDelay = $true
    $global:__SOCKET__ = @{ client = $client; stream = $client.GetStream() }
} catch {
    $client.Dispose()
    throw
}
