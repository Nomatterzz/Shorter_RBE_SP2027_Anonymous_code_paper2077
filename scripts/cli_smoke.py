#!/usr/bin/env python3
"""Separate-process persistent CLI workflow, including a real merge and replay."""
import argparse,json,os,stat,subprocess,tempfile
from pathlib import Path
if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default=str(ROOT/'build/rbe_cli'));p.add_argument('--preset',default='toy');p.add_argument('--out',default=str(ROOT/'results/cli_smoke.json'));a=p.parse_args();binary=str(Path(a.binary).resolve())
    def run(*args,fail=False):
        r=subprocess.run([binary,*map(str,args)],capture_output=True,text=True)
        assert (r.returncode!=0)==fail,(args,r.stdout,r.stderr)
        return r
    with tempfile.TemporaryDirectory(prefix='rbe-cli-test-') as tmp:
        tmp=Path(tmp);directory=tmp/'registry';params=json.loads(run('params','--preset',a.preset).stdout);L=params['L'];ids=['0'*L,'0'*(L-1)+'1']
        run('setup','--dir',directory,'--preset',a.preset)
        for i in range(2):run('keygen','--dir',directory,'--out',tmp/f'user{i}')
        run('register','--dir',directory,'--id',ids[0],'--public-key',tmp/'user0.pk')
        run('witness','--dir',directory,'--id',ids[0],'--out',tmp/'witness1.bin')
        state1=(directory/'state.bin').read_bytes();(tmp/'state1.bin').write_bytes(state1)
        message=os.urandom(params['phi']//8);(tmp/'message.bin').write_bytes(message)
        run('encrypt','--dir',directory,'--id',ids[0],'--message',tmp/'message.bin','--out',tmp/'old.ct')
        run('register','--dir',directory,'--id',ids[1],'--public-key',tmp/'user1.pk')
        run('witness','--dir',directory,'--id',ids[0],'--version','1','--out',tmp/'replayed.bin')
        assert (tmp/'replayed.bin').read_bytes()==(tmp/'witness1.bin').read_bytes()
        run('decrypt','--dir',directory,'--secret-key',tmp/'user0.sk','--witness',tmp/'replayed.bin','--ciphertext',tmp/'old.ct','--out',tmp/'old.out')
        assert (tmp/'old.out').read_bytes()==message
        run('witness','--dir',directory,'--id',ids[0],'--out',tmp/'current.w')
        run('encrypt','--dir',directory,'--id',ids[0],'--message',tmp/'message.bin','--out',tmp/'new.ct')
        run('decrypt','--dir',directory,'--secret-key',tmp/'user0.sk','--witness',tmp/'current.w','--ciphertext',tmp/'new.ct','--out',tmp/'new.out')
        assert (tmp/'new.out').read_bytes()==message
        assert len((tmp/'new.ct').read_bytes())==params['ciphertext_bytes']
        assert stat.S_IMODE((tmp/'user0.sk').stat().st_mode)==0o600
        log=(directory/'registry.log').read_bytes();state=(directory/'state.bin').read_bytes()
        run('register','--dir',directory,'--id',ids[0],'--public-key',tmp/'user0.pk',fail=True)
        assert (directory/'registry.log').read_bytes()==log and (directory/'state.bin').read_bytes()==state
        run('encrypt','--dir',directory,'--id','invalid','--message',tmp/'message.bin','--out',tmp/'bad.ct',fail=True)
        assert not (tmp/'bad.ct').exists()
        run('keygen','--dir',directory,'--out',tmp/'user0',fail=True)
    result={'separate_process_workflow':True,'preset':a.preset,'default_CSPRNG':True,'actual_binary_merge':True,'historical_replay':True,'duplicate_registration_nonmutating':True,'secret_file_mode':'0600','current_ciphertext_bytes':params['ciphertext_bytes']}
    Path(a.out).parent.mkdir(parents=True,exist_ok=True);Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
