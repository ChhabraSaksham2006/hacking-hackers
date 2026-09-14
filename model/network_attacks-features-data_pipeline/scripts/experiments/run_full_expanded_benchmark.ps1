$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$log = Join-Path $root 'results\expanded_benchmark.log'
Set-Location $root
"Expanded benchmark started $(Get-Date -Format o)" | Out-File $log -Encoding utf8
$horizons = @(1,3,5,10,25,50,100,200)
foreach ($k in $horizons) {
  "BASELINE K=$k $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
  & python -u scripts\experiments\run_baseline_suite.py --horizon $k 2>&1 | Tee-Object -FilePath $log -Append
  if ($LASTEXITCODE -ne 0) { throw "Baseline K=$k failed with exit code $LASTEXITCODE" }
  Copy-Item reports\baselines\06_multihorizon_comparison.csv ("reports\baselines\06_multihorizon_comparison_k{0}.csv" -f $k) -Force
}
"RSSM MATRIX $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
& python -u scripts\experiments\run_sparse_rssm.py --run-all 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "RSSM matrix failed with exit code $LASTEXITCODE" }
& python scripts\experiments\compare_sparse_rssm.py 2>&1 | Tee-Object -FilePath $log -Append
"Expanded benchmark finished $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
