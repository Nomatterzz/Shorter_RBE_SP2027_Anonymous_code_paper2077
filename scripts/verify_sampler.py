#!/usr/bin/env python3
"""Regenerate certified CDT tables and cross-check C++ exp intervals."""
import argparse,csv,io,json,subprocess
from pathlib import Path
from certified_math import pi_interval,exp_negative_interval,ceildiv
from generate_gaussian_tables import generate
if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'build/rbe_cli'));p.add_argument('--out',default=str(ROOT/'results/sampler.json'));a=p.parse_args()
    header,manifest=generate();assert (ROOT/'include/rbe/gaussian_tables.hpp').read_text()==header;assert (ROOT/'data/gaussian_tables.json').read_text()==manifest
    raw=subprocess.check_output([a.binary,'gaussian-vectors'],text=True);rows=0;maxwidth=0;piL,piU=pi_interval(896)
    for v in csv.DictReader(io.StringIO(raw)):
        k,j,t,P,lo,hi=[int(v[f]) for f in ['k','j','t','P','lower','upper']]
        pl,pu=piL>>(896-P),ceildiv(piU,1<<(896-P));num=2*k*t*j+j*j;den=1024*t*t
        assert exp_negative_interval(pl*num//den,ceildiv(pu*num,den),P)==(lo,hi)
        if P==384:maxwidth=max(maxwidth,hi-lo);assert hi-lo<=(1<<32)
        rows+=1
    assert rows==120
    result={'CDT_thresholds_regenerated':True,'interval_precision':896,'threshold_bits':256,'acceptance_interval_crosschecks':rows,'maximum_observed_384bit_interval_width':maxwidth,'per_sample_TV_analytic_bound':'2^-240 under independent ideal bits','scope':'interval and distribution checks; finite statistical smoke tests are not a DFR measurement'}
    Path(a.out).parent.mkdir(parents=True,exist_ok=True);Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
