#!/usr/bin/env python3
"""Validate deterministic full-parameter KATs or explicitly establish a baseline."""
import argparse,json,re,subprocess
from pathlib import Path
if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'build/rbe_tests'));p.add_argument('--record',action='store_true');p.add_argument('--log');p.add_argument('--out',default=str(ROOT/'results/kats.json'));a=p.parse_args()
    text=Path(a.log).read_text() if a.log else subprocess.check_output([a.binary,'--all'],text=True)
    rows={m[0]:{'parameters_sha256':m[1],'ciphertext_sha256':m[2]} for m in re.findall(r'^KAT (\S+) pp ([0-9a-f]{64}) ct ([0-9a-f]{64})$',text,re.M)}
    assert set(rows)=={'main','matched','two-independent','two-radix','published-gadget'}
    path=ROOT/'data/known_answer_tests.json'
    if a.record:path.write_text(json.dumps({'format':1,'seed_rule':'full-parameter-<preset>; publicly known TEST-ONLY keys','vectors':rows},indent=2,sort_keys=True)+'\n')
    else:assert rows==json.loads(path.read_text())['vectors'],'KAT drift'
    result={'all_presets_match':True,'count':len(rows),'recorded_baseline':a.record};Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
