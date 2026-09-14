$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$final = Join-Path $root 'results_final'
$log = Join-Path $final 'run.log'
New-Item -ItemType Directory -Force -Path $final | Out-Null
Set-Location $root
"results_final started $(Get-Date -Format o)" | Out-File $log -Encoding utf8
$horizons = @(1,3,5,10,25,50,100,200)
foreach ($k in $horizons) {
  "BASELINE K=$k $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
  & python -u scripts\experiments\run_baseline_suite.py --horizon $k 2>&1 | Tee-Object -FilePath $log -Append
  if ($LASTEXITCODE -ne 0) { throw "Baseline K=$k failed" }
  $dest = Join-Path $final 'baselines'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item reports\baselines\*.csv, reports\baselines\*.md $dest -Force -ErrorAction SilentlyContinue
  Copy-Item reports\baselines\06_multihorizon_comparison.csv (Join-Path $dest ("06_multihorizon_comparison_k{0}.csv" -f $k)) -Force
}
"RSSM MATRIX $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
& python -u scripts\experiments\run_sparse_rssm.py --run-all --results-dir results_final\sparse_rssm 2>&1 | Tee-Object -FilePath $log -Append
if ($LASTEXITCODE -ne 0) { throw "RSSM matrix failed" }
& python scripts\experiments\compare_sparse_rssm.py --rssm-dir results_final\sparse_rssm --baseline-dir results_final\baselines --out-dir results_final\comparison 2>&1 | Tee-Object -FilePath $log -Append
"results_final finished $(Get-Date -Format o)" | Tee-Object -FilePath $log -Append
