function Dll-Loader {
    param([switch]$smb, [switch]$local, [switch]$http, [string]$path)

    $help=@"
.SYNOPSIS
    dll loader.
    PowerShell Function: Dll-Loader
    Author: Hector de Armas (3v4Si0N)

    Required dependencies: None
    Optional dependencies: None
.DESCRIPTION
    .
.EXAMPLE
    Dll-Loader -smb -path \\192.168.139.132\\share\\myDll.dll
    Dll-Loader -local -path C:\Users\Pepito\Desktop\myDll.dll
    Dll-Loader -http -path http://example.com/myDll.dll

    Description
    -----------
    Function that loads an arbitrary dll
"@

    if (($smb -eq $false -and $local -eq $false -and $http -eq $false) -or ($path -eq "" -or $path -eq $null))
    {
        write-host "$help`n"
    }
    else
    {

        if ($http)
        {
            Write-Host "[+] Reading dll by HTTP"
            $webclient = [Net.WebClient]::new()
            $dll = $webclient.DownloadData($path)
        }
        else
        {
            if($smb){ Write-Host "[+] Reading dll by SMB" }
            else { Write-Host "[+] Reading dll locally" }

            $dll = [System.IO.File]::ReadAllBytes($path)
        }
        

        if ($dll -ne $null)
        {
            Write-Host "[+] Loading dll..."
            $assembly_loaded = [System.Reflection.Assembly]::Load($dll)
            $obj = (($assembly_loaded.GetExportedTypes() | Select-Object DeclaredMethods ).DeclaredMethods | Where-Object {$_.ispublic -eq $true} | Select-Object DeclaringType,name -Unique -ErrorAction SilentlyContinue )
            [array]$methods = foreach ($assemblyproperties in $obj) { $namespace = $assemblyproperties.DeclaringType.tostring(); $metodo = $assemblyproperties.name.tostring(); "[" + $namespace + "]" + "::" + $metodo + "()" }
            $methods = $methods | Select-Object -Unique ; $global:showmethods =   ($methods| where { $global:showmethods  -notcontains $_}) | foreach {"$_`n"}
            
        }
    }
}