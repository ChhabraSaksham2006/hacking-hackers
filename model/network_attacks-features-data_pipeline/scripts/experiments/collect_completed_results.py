"""Collect completed baseline/RSSM artifacts into comparison CSV/JSON/TXT."""
from __future__ import annotations
import argparse
import re, json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.experiments.run_selected_baseline_rssm import write_comparison

def collect_baseline_logs(out: Path):
    """Archive parsed baseline log metrics so overwritten shared CSVs do not lose rows."""
    archive = out / 'baseline_log_metrics.jsonl'
    rows=[]
    for log in sorted((out/'logs').glob('baseline_*.log')):
        text=log.read_text(encoding='utf-8', errors='ignore')
        for line in text.splitlines():
            m=re.search(r'(?P<model>Persistence|LR|RF|Transformer).*?K=(?P<k>\d+).*?Test F1:\s*(?P<f1>[0-9.]+)',line)
            if not m: continue
            f1=float(m.group('f1')); rm=re.search(r'(?:Rec|Recall):\s*([0-9.]+)',line); rec=float(rm.group(1)) if rm else None
            prec=(f1*rec/(2*rec-f1)) if rec is not None and 2*rec>f1 else None
            rows.append({'Model':m.group('model'),'K':int(m.group('k')),'Attack F1':f1,'Precision':prec,'Recall':rec,'FPR':None,'Source':str(log)})
    archive.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
    return rows


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results-dir', type=Path, default=ROOT / 'results_selected_benchmark')
    args = p.parse_args()
    out = args.results_dir if args.results_dir.is_absolute() else ROOT / args.results_dir
    if not out.exists():
        raise SystemExit(f'Results directory does not exist: {out}')
    collect_baseline_logs(out)
    write_comparison(out)
    print(f'Collected completed results from: {out}')
    print(f'Comparison files: {out / "comparison"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
