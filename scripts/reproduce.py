#!/usr/bin/env python3
"""Reviewer entry point: fail-fast, logged, no network, no hidden datasets."""
import argparse,json,os,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary-dir',default='build');p.add_argument('--out-dir',default='results/local');a=p.parse_args();binarydir=Path(a.binary_dir).resolve();out=Path(a.out_dir).resolve();out.mkdir(parents=True,exist_ok=True);cli=binarydir/'rbe_cli';test=binarydir/'rbe_tests';steps=[]
    def run(name,args):
        started=time.monotonic();r=subprocess.run([str(x) for x in args],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        (out/(name+'.txt')).write_text(r.stdout)
        steps.append({'name':name,'returncode':r.returncode,'passed':r.returncode==0,'seconds':time.monotonic()-started,'log':name+'.txt'})
        report={'format':1,'all_passed':all(x['passed'] for x in steps),'steps':steps,'not_claimed':['Docker execution','remote GitHub Actions execution','fresh lattice-estimator run','upstream KLSS runtime comparison','empirical measurement of a 2^-143 failure probability','billion-user live population benchmark']}
        (out/'SELF_CHECK.json').write_text(json.dumps(report,indent=2)+'\n')
        print(f"{name}: {'PASS' if not r.returncode else 'FAIL'} ({steps[-1]['seconds']:.3f}s)",flush=True)
        if r.returncode:print(r.stdout);raise SystemExit(r.returncode)
    run('cpp_all',[test,'--all'])
    run('known_answers',[sys.executable,'scripts/verify_kats.py','--log',out/'cpp_all.txt','--out',out/'kats.json'])
    run('parameter_certificates',[sys.executable,'scripts/verify_parameters.py','--binary',cli,'--out',out/'parameters.json'])
    run('gaussian_certificates',[sys.executable,'scripts/verify_sampler.py','--binary',cli,'--out',out/'sampler.json'])
    run('independent_quantizer',[sys.executable,'scripts/verify_quantizer.py','--binary',cli,'--out',out/'quantizer.json'])
    run('persistent_cli_toy',[sys.executable,'scripts/cli_smoke.py','--binary',cli,'--out',out/'cli_toy.json'])
    run('persistent_cli_main',[sys.executable,'scripts/cli_smoke.py','--binary',cli,'--preset','main','--out',out/'cli_main.json'])
    for preset in ['toy','main']:
        with tempfile.TemporaryDirectory(prefix='anonymous-rbe-oracle-') as tmp:
            dest=Path(tmp)/'demo'
            run('demo_'+preset,[cli,'demo','--preset',preset,'--out',dest,'--test-seed','independent-oracle-'+preset])
            run('python_oracle_'+preset,[sys.executable,'scripts/reference_verify.py',dest,'--out',out/('oracle_'+preset+'.json')])
    print('All requested reproduction checks passed.',flush=True)
if __name__=='__main__':main()
