#!/usr/bin/env python3
"""Independent Python big-integer ring arithmetic and serialized-data oracle.
Does not call the C++ ring/NTT backend. Input: rbe_cli demo directory.
"""
import argparse,json,hashlib
from pathlib import Path

if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")

def product(a,b):
    n=len(a);assert len(b)==n
    def positive(x,y):
        maximum=max(x,default=0)*max(y,default=0)*n
        if not maximum:return [0]*n
        shift=maximum.bit_length()+1;mask=(1<<shift)-1
        xx=sum(v<<(shift*i) for i,v in enumerate(x));yy=sum(v<<(shift*i) for i,v in enumerate(y));z=xx*yy
        return [((z>>(shift*i))&mask)-((z>>(shift*(i+n)))&mask) for i in range(n)]
    # All serialized ring operands a are nonnegative; b may be signed.
    assert min(a,default=0)>=0
    pos=positive(a,[max(v,0) for v in b]);neg=positive(a,[max(-v,0) for v in b]);return [x-y for x,y in zip(pos,neg)]

def packed(blob,count,bits):
    assert len(blob)==(count*bits+7)//8
    acc=at=used=0;v=[];mask=(1<<bits)-1
    for _ in range(count):
        while used<bits:acc|=blob[at]<<used;at+=1;used+=8
        v.append(acc&mask);acc>>=bits;used-=bits
    assert acc==0
    return v

def grouped(v,n):return [v[i:i+n] for i in range(0,len(v),n)]
def params(dir):return json.loads((dir/'params.json').read_text())
def decompose(a,p):
    q=p['q'];a=a if a<=q//2 else a-q;g=p['scales']
    if p['decomposition']=='one':return [-((a+g[0]//2)//g[0])]
    if p['decomposition']=='independent':
        high=-((a+g[1]//2)//g[1]);r=a+g[1]*high;return [-((r+g[0]//2)//g[0]),high]
    base=p['radix'];H=sum((base//2)*base**i for i in range(p['digits']));v=(a+H)%q;u=[]
    for i in range(p['digits']):
        x=v%base-base//2;v//=base
        if i>=p['dropped']:u.append(-x)
    return u

def verify(dir):
    p=params(dir);n,phi,L,q,B,K,U,k=[p[x] for x in ['n','phi','L','q','B','K','U','kappa']];d=len(p['scales']);width=3*n*d;counter=p['counter_bytes'];M=1<<k;qb=(q.bit_length()+7)//8
    def qpolys(blob):
        assert len(blob)%(qb*phi)==0
        v=[int.from_bytes(blob[i:i+qb],'little') for i in range(0,len(blob),qb)];assert all(x<q for x in v);return grouped(v,phi)
    pp=qpolys((dir/'parameters.bin').read_bytes());A=grouped(pp[:n*width],width);P=grouped(pp[n*width:n*width+n*n],n)
    assert len(pp)==n*width+n*n+n*B
    pk=qpolys((dir/'public.key').read_bytes());sk=grouped([x-K for x in packed((dir/'secret.key').read_bytes(),n*phi,(2*K).bit_length())],phi);assert all(-K<=x<=K for a in sk for x in a)
    def matvec(mat,v):
        out=[]
        for row in mat:
            acc=[0]*phi
            for a,b in zip(row,v):acc=[x+y for x,y in zip(acc,product(a,b))]
            out.append([x%q for x in acc])
        return out
    reconstructed=matvec(P,sk)
    noise=[(pk[i][j]-reconstructed[i][j])%q for i in range(n) for j in range(phi)];noise=[x if x<=q//2 else x-q for x in noise];assert all(abs(x)<=K for x in noise)
    identity=(dir/'identity.txt').read_text().strip();assert len(identity)==L and set(identity)<=set('012')
    message=packed((dir/'message.bin').read_bytes(),phi,1);reports=[]
    for prefix in ['', 'historical-']:
        sb=(dir/(prefix+'state.bin')).read_bytes();version=int.from_bytes(sb[:counter],'little');roots=grouped(qpolys(sb[counter:]),n)
        wb=(dir/(prefix+'witness.bin')).read_bytes();created=int.from_bytes(wb[:counter],'little');slot=wb[counter];assert 0<created<=version<=p['capacity'] and slot<B
        uv=packed(wb[counter+1:],L*width*phi,(2*U).bit_length());assert all(x<=2*U for x in uv);opening=grouped([x-U for x in uv],phi)
        label=pk
        for j in range(L-1,-1,-1):
            node=opening[j*width:(j+1)*width];child=int(identity[j]);chosen=node[child*n*d:(child+1)*n*d]
            for i in range(n):
                for z in range(phi):assert [chosen[i*d+t][z] for t in range(d)]==decompose(label[i][z],p)
            label=matvec(A,node)
        assert label==roots[slot]
        cb=(dir/(prefix+'ciphertext.bin')).read_bytes();assert int.from_bytes(cb[:counter],'little')==version and len(cb)==p['ciphertext_bytes'];cv=grouped(packed(cb[counter:],(L*width+n+B)*phi,k),phi)
        out=list(cv[L*width+n+slot])
        for a,b in zip(cv[:L*width+n],opening+sk):out=[x-y for x,y in zip(out,product(a,b))]
        decoded=[(((v%M+M//4)//(M//2))&1) for v in out];assert decoded==message
        reports.append({'snapshot':version,'bucket':slot,'path_relation':True,'decryption_matches':True,'ciphertext_sha256':hashlib.sha256(cb).hexdigest()})
    return {'preset':p['preset'],'method':'Python Kronecker-substitution integer products; no C++ NTT','key_relation':True,'current_and_historical':reports}

def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--out',type=Path);a=p.parse_args();r=verify(a.directory);s=json.dumps(r,indent=2)+'\n';print(s)
    if a.out:a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(s)
if __name__=='__main__':main()
