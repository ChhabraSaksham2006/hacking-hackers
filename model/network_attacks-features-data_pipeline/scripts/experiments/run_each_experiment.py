"""Track every baseline/RSSM model-horizon experiment separately.

Each task gets its own subprocess, log, marker, and tqdm bar.  The existing
baseline implementation trains its baseline family together for a selected K;
those tasks are therefore labelled ``baseline_suite:<K>`` and remain directly
comparable, while every RSSM sparsity/attention/K configuration is independent.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HORIZONS = [1, 3, 5, 10, 25, 50, 100, 200]
RSSM = [("top05", .05, False), ("top10", .10, False), ("top25", .25, False),
        ("top50", .50, False), ("dense", 1.0, False), ("top10_attn", .10, True)]
try:
    from tqdm import tqdm
except ImportError:
    class tqdm:
        def __init__(self, it=None, **kw): self.it = it
        def __iter__(self): return iter(self.it) if self.it is not None else iter(())
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def update(self, n=1): pass
        def set_postfix_str(self, *a, **k): pass
        def close(self): pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results-dir', type=Path, default=ROOT/'results_final')
    ap.add_argument('--epochs', type=int, default=20)
    ap.add_argument('--batch-size', type=int, default=512)
    ap.add_argument('--no-resume', action='store_true')
    ap.add_argument('--stream', action='store_true', help='Print subprocess training output live.')
    ap.add_argument('--horizon', type=int, choices=HORIZONS, help='Run only one forecast horizon.')
    ap.add_argument('--skip-gru', action='store_true', help='Skip the GRU baseline task.')
    ap.add_argument('--rssm-sparsities', type=float, nargs='+', default=None,
                    help='RSSM sparsity ratios to run (default: all configured ratios).')
    args = ap.parse_args()
    out = args.results_dir if args.results_dir.is_absolute() else ROOT/args.results_dir
    out.mkdir(parents=True, exist_ok=True)
    logdir = out/'individual_logs'; logdir.mkdir(exist_ok=True)
    baseline_models = ['persistence', 'logistic', 'random_forest', 'gru', 'transformer']
    if args.skip_gru:
        baseline_models.remove('gru')
    hs = [args.horizon] if args.horizon is not None else HORIZONS
    tasks = [(f'baseline_{m}_k{k}', 'baseline', k, m, False) for m in baseline_models for k in hs]
    rssm_configs = RSSM if args.rssm_sparsities is None else [
        cfg for cfg in RSSM if any(abs(cfg[1] - requested) < 1e-8 for requested in args.rssm_sparsities)
    ]
    tasks += [(f'{name}_k{k}', 'rssm', k, ratio, attn) for name,ratio,attn in rssm_configs for k in hs]
    manifest = {'epochs': args.epochs, 'batch_size': args.batch_size, 'tasks': [t[0] for t in tasks], 'started': time.time()}
    (out/'individual_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    for name, kind, k, ratio, attn in tasks:
        marker = out/'individual_done'/f'{name}.json'; marker.parent.mkdir(exist_ok=True)
        if marker.exists() and not args.no_resume:
            continue
        bar = tqdm(total=1, desc=name, unit='task', leave=True)
        logfile = logdir/f'{name}.log'
        if kind == 'baseline':
            cmd = [sys.executable, 'scripts/experiments/run_baseline_suite.py', '--horizon', str(k), '--epochs', str(args.epochs), '--only-model', ratio]
        else:
            cmd = [sys.executable, 'scripts/experiments/run_sparse_rssm.py', '--sparsity', str(ratio), '--horizon', str(k), '--epochs', str(args.epochs), '--batch-size', str(args.batch_size), '--results-dir', str(out/'sparse_rssm')]
            if attn: cmd.append('--use-attention')
        started = time.time()
        print(f"\nTRAINING STARTED: {name}")
        with logfile.open('w', encoding='utf-8') as fh:
            fh.write('$ ' + ' '.join(map(str, cmd)) + '\n')
            if args.stream:
                proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                assert proc.stdout is not None
                for line in proc.stdout:
                    print(f"[{name}] {line.rstrip()}", flush=True)
                    fh.write(line)
                rc = proc.wait()
            else:
                rc = subprocess.run(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT).returncode
        if rc:
            bar.set_postfix_str('FAILED'); bar.close()
            raise SystemExit(f'{name} failed (exit {rc}); see {logfile}')
        marker.write_text(json.dumps({'task': name, 'kind': kind, 'horizon': k, 'sparsity': ratio, 'attention': attn, 'seconds': time.time()-started}, indent=2), encoding='utf-8')
        bar.update(1); bar.set_postfix_str('complete'); bar.close()
        print(f"TRAINING ENDED: {name} ({time.time()-started:.1f}s)", flush=True)
    manifest['finished'] = time.time()
    (out/'individual_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(f'All individual tasks complete: {out}')

if __name__ == '__main__': main()
