# Read-only sampler for the installed UDCSAgent: one CSV row every $Every seconds.
param([int]$Minutes = 40, [int]$Every = 15, [string]$Out)
$svcPid = (Get-CimInstance Win32_Service -Filter "Name='UDCSAgent'").ProcessId
"time,pid,ws_mib,peak_ws_mib,private_mib,handles,threads,cpu_s" | Set-Content -Encoding ascii $Out
$end = (Get-Date).AddMinutes($Minutes)
while ((Get-Date) -lt $end) {
    $p = Get-Process -Id $svcPid -ErrorAction SilentlyContinue
    if (-not $p) { "{0:o},{1},gone" -f (Get-Date), $svcPid | Add-Content -Encoding ascii $Out; break }
    $cpu = try { $p.TotalProcessorTime.TotalSeconds } catch { '' }
    '{0:o},{1},{2:F2},{3:F2},{4:F2},{5},{6},{7}' -f (Get-Date), $svcPid, ($p.WorkingSet64/1MB), ($p.PeakWorkingSet64/1MB), ($p.PrivateMemorySize64/1MB), $p.HandleCount, $p.Threads.Count, $cpu | Add-Content -Encoding ascii $Out
    Start-Sleep -Seconds $Every
}
