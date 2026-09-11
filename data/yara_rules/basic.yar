rule Suspicious_Shell_Exec
{
    meta:
        description = "Binarka zawiera wywolania funkcji shell (system/popen/execve)"
        severity = "medium"
    strings:
        $a = "system("
        $b = "popen("
        $c = "execve("
    condition:
        any of them
}

rule Suspicious_Network_Capability
{
    meta:
        description = "Mozliwe wykorzystanie gniazd sieciowych (socket/connect/bind)"
        severity = "low"
    strings:
        $a = "socket"
        $b = "connect"
        $c = "bind"
    condition:
        2 of them
}

rule Contains_Base64_Blob
{
    meta:
        description = "Wykryto dlugi ciag przypominajacy dane zakodowane w Base64 - mozliwa ukryta ladownosc"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,500}={0,2}/
    condition:
        $b64
}

rule Possible_UPX_Packer
{
    meta:
        description = "Wykryto sygnature charakterystyczna dla pakera UPX - binarka moze byc spakowana/zaciemniona"
        severity = "high"
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
    condition:
        any of them
}

rule Suspicious_Reverse_Shell_Strings
{
    meta:
        description = "Wykryto ciagi charakterystyczne dla reverse shell (np. /dev/tcp, nc -e, bash -i)"
        severity = "high"
    strings:
        $a = "/dev/tcp/"
        $b = "nc -e"
        $c = "bash -i"
    condition:
        any of them
}
