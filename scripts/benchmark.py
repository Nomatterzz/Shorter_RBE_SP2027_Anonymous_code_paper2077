#!/usr/bin/env python3
"""Run same-backend, same-machine controls. Never imports KLSS timings."""
import argparse,csv,json,os,platform,statistics,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
PRESETS=['main','matched','two-independent','two-radix','published-gadget']
def environment():
    cpu='unavailable';mem=None
    if Path('/proc/cpuinfo').exists():
        cpu=next((x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),cpu)
    if Path('/proc/meminfo').exists():mem=next((x.split(':',1)[1].strip() for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemTotal:')),None)
    return {'cpu_model':cpu,'logical_cpus':os.cpu_count(),'affinity_cpu_count':len(os.sched_getaffinity(0)) if hasattr(os,'sched_getaffinity') else None,'memory_total':mem,'system':platform.system(),'kernel':platform.release(),'architecture':platform.machine(),'python':platform.python_version(),'measurement_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'parallel_scheme_threads':1,'clock':'steady_clock wall time','host_type':'shared/containerized execution environment; not a controlled dedicated bare-metal benchmark','hostname_recorded':False}

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'build/rbe_cli'));p.add_argument('--out-dir',default=str(ROOT/'results/benchmarks'));p.add_argument('--iterations',type=int,default=5);p.add_argument('--users',type=int,default=4);p.add_argument('--presets',nargs='+',default=PRESETS);a=p.parse_args();out=Path(a.out_dir);out.mkdir(parents=True,exist_ok=True);(out/'environment.json').write_text(json.dumps(environment(),indent=2)+'\n');rows=[]
    for preset in a.presets:
        path=out/(preset+'.json');subprocess.run([a.binary,'benchmark','--preset',preset,'--users',str(a.users),'--iterations',str(a.iterations),'--out',str(path)],check=True)
        r=json.loads(path.read_text());assert r['randomness']=='OpenSSL RAND_priv_bytes';row={'preset':preset,'capacity':r['capacity'],'actual_registered_users':a.users,'iterations':a.iterations,'ciphertext_bytes':r['runs'][0]['ciphertext_bytes'],'setup_ms':r['setup_ms'],'public_preparation_ms':r['public_preparation_ms'],'peak_rss_kib':max(x['peak_rss_kib'] for x in r['runs'])}
        for field in ['keygen_per_user_ms','registration_total_ms','witness_ms','encrypt_ms','encrypt_and_serialize_ms','decrypt_ms','parse_and_decrypt_ms']:
            values=[x[field] for x in r['runs']];row[field+'_median']=statistics.median(values);row[field+'_mean']=statistics.mean(values);row[field+'_stdev']=statistics.stdev(values) if len(values)>1 else 0
        rows.append(row)
    (out/'summary.json').write_text(json.dumps(rows,indent=2)+'\n')
    with (out/'summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    lines=['# Measured same-backend results','',f'Actual registry population: {a.users}. Independent trials: {a.iterations}. Single-threaded C++20. Default OpenSSL CSPRNG.','', '| Preset | Ciphertext bytes | Enc + serialization median (ms) | Parse + Dec median (ms) | Peak RSS (MiB) |','|---|---:|---:|---:|---:|']
    for r in rows:lines.append(f"| {r['preset']} | {r['ciphertext_bytes']:,} | {r['encrypt_and_serialize_ms_median']:.3f} | {r['parse_and_decrypt_ms_median']:.3f} | {r['peak_rss_kib']/1024:.2f} |")
    lines+=['','The `main` capacity is 2^30 with 31 slots, not a claim that 2^30 users were registered in memory. Compare `matched` and the retuned controls at 30 slots.','', 'Setup, public NTT preparation, registration, witness generation and serialization are separately recorded. Encryption includes all randomness and Gaussian/quantizer work. Decryption includes exact CRT arithmetic. CLI startup/log replay and filesystem I/O are not in these in-memory algorithm timings.','', 'These are fresh same-backend controls. No upstream KLSS Rust runtime was measured, and no speedup over that implementation is claimed.','', 'Raw trials, standard deviations and environment metadata accompany this summary. Shared-host scheduling affects absolute times.']
    (out/'SUMMARY.md').write_text('\n'.join(lines)+'\n');print('\n'.join(lines))
if __name__=='__main__':main()
