#!/usr/bin/env python3
"""Repository content hygiene; cannot inspect GitHub account/commit identity."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IGNORED={'build','build-clang','build-sanitize','_work','.git','__pycache__'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--forbid',action='append',default=[]);p.add_argument('--out',default=str(ROOT/'results/anonymity_audit.json'));a=p.parse_args();issues=[];count=0
    for path in ROOT.rglob('*'):
        relative=path.relative_to(ROOT)
        if any(part in IGNORED or part.startswith('build-') for part in relative.parts) or not path.is_file():continue
        if relative.parts[:2]==('results','local'):continue
        if path.suffix in {'.sk','.key','.pk','.ct','.bin','.zip','.pem'}:issues.append({'path':str(relative),'kind':'generated/private/binary file requiring exclusion'});continue
        try:text=path.read_text()
        except UnicodeDecodeError:continue
        count+=1
        if str(relative)=='scripts/anonymity_audit.py':continue
        for secret in [r'gh[pousr]_[A-Za-z0-9_]{20,}',r'github_pat_[A-Za-z0-9_]{20,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----']:
            if re.search(secret,text):issues.append({'path':str(relative),'kind':'credential pattern'})
        if re.search(r'/mnt/data/|/home/(?!artifact\b)[A-Za-z0-9_-]+/',text):issues.append({'path':str(relative),'kind':'absolute execution/user path'})
        for word in a.forbid:
            if word.casefold() in text.casefold():issues.append({'path':str(relative),'kind':'forbidden identifying string','term':word})
    result={'text_files_checked':count,'issues':issues,'passed':not issues,'manual_checks_still_required':['Git commit author/committer/email and signatures','GitHub account owner, activity and profile','repository remotes, issue/CI metadata and historical releases','paper submission metadata and artifact URL ownership']}
    Path(a.out).parent.mkdir(parents=True,exist_ok=True);Path(a.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(bool(issues))
if __name__=='__main__':main()
