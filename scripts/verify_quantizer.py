#!/usr/bin/env python3
"""Independent exact integration of the triangular rounding kernel."""
import argparse,csv,io,json,subprocess
from fractions import Fraction as F
from pathlib import Path
if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")
ROOT=Path(__file__).resolve().parents[1]
def kernel_integral(a,b,k):
    total=F(0)
    l=max(a,F(k-1));r=min(b,F(k))
    if l<r:total+=(r-l)*(l+r-2*(k-1))/2
    l=max(a,F(k));r=min(b,F(k+1))
    if l<r:total+=(r-l)*(2*(k+1)-l-r)/2
    return total

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'build/rbe_cli'));p.add_argument('--out',default=str(ROOT/'results/quantizer_independent.json'));a=p.parse_args()
    raw=subprocess.check_output([a.binary,'quantizer-vectors','--qmax','64'],text=True);rows=0;pairs=set();marginals={}
    for row in csv.DictReader(io.StringIO(raw)):
        q,M,x,D=[int(row[k]) for k in ['q','M','a','denominator']];left,right=F(M*(2*x-1),2*q),F(M*(2*x+1),2*q)
        observed={};moment=second=F(0);marg=marginals.setdefault((q,M),[F(0)]*M)
        for i in range(3):
            k,w=int(row['k'+str(i)]),int(row['w'+str(i)])
            if not w:continue
            mass=F(w,D);assert kernel_integral(left,right,k)/(right-left)==mass
            observed[k]=mass;err=F(q*k,M)-x;moment+=mass*err;second+=mass*err*err;marg[k%M]+=mass/q
        assert sum(observed.values())==1 and moment==0 and second<=F(q*q,4*M*M)+F(1,12)
        rows+=1;pairs.add((q,M))
    for (q,M),marg in marginals.items():assert all(x==F(1,M) for x in marg)
    assert rows==87360 and len(pairs)==2016
    result={'method':'exact rational integration, independent of the C++ weight formulas','modulus_pairs':len(pairs),'input_rows':rows,'mass_mean_variance_and_uniformity':True}
    Path(a.out).parent.mkdir(parents=True,exist_ok=True);Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
