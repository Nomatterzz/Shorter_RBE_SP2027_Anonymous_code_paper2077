#!/usr/bin/env python3
"""Recompute sizes and ideal/finite-sampler error bounds; no estimator claims.
Decimal values are descriptive. Fractions certify sufficient inequalities.
"""
import argparse,json,subprocess
from pathlib import Path
from decimal import Decimal,localcontext
from fractions import Fraction as F
from certified_math import pi_interval,log_interval,sqrt_interval,exp_negative_interval
if not __debug__:
    raise RuntimeError("Verification must not run with Python optimization enabled")
ROOT=Path(__file__).resolve().parents[1]
PRESETS=['main','matched','two-independent','two-radix','published-gadget']
PI_LO,PI_HI=pi_interval(512)
PL,PU=F(PI_LO,1<<512),F(PI_HI,1<<512)
LN2L,LN2U=log_interval(F(2))
def D(x):
    if isinstance(x,F):return Decimal(x.numerator)/Decimal(x.denominator)
    return Decimal(x)
def evaluate(p):
    phi,n,L,q,B,k,K,U,V,s,st=[p[x] for x in ['phi','n','L','q','B','kappa','K','U','V','sigma','sigma_tilde']]
    d=len(p['scales']);M=1<<k;source_columns=max(3*d*n+B,n+B+1);dimension=phi*(n+source_columns)
    C=163**2*n*B*((V+K)**2+3*U**2 if d==1 else max(V**2+6*U**2,(V+K)**2+K**2))
    # csc(pi/(2 phi)) < 163 follows from sin(x) >= x-x^3/6.
    x=PL/(2*phi);assert x-x**3/6>F(1,163)
    if d==1:assert K*K<=3*U*U
    hlo,hhi=log_interval(F(2*dimension*((1<<160)+1)))
    hU=hhi/PL
    sqrt2L,sqrt2U=sqrt_interval(2)
    source_width_squared_L=128*sqrt2L;source_width_squared_U=128*sqrt2U
    lhs=F(C,st*st-s*s)+F(1,s*s)
    rhs_lower=1/(2*hU+source_width_squared_U)
    assert lhs<rhs_lower and source_width_squared_L>=2*hU
    assert s*s>=2*hU and st*st-s*s>=2*hU
    VG_U=F(st*st+s*s*n*phi*(L*V*V+2*V*K+2*K*K+3*d*L*U*U),1)/(2*PL)
    VQ= (F(q*q,4*M*M)+F(1,12))*(1+phi*(3*d*L*n*U*U+n*K*K))
    T=F(q,4)-F(1,2)
    tail_exponent_lower=T*T/(2*(VG_U+VQ))
    _,lnprefactorU=log_interval(F(2*phi*B))
    # Rigorous ideal DFR < 2^-k_cert, separate from decimal display.
    ideal_bits=0
    while tail_exponent_lower>lnprefactorU+(ideal_bits+1)*LN2U:ideal_bits+=1
    gaussians=((L+1)*n+(3*d*n*L+n)+B)*phi
    finite_tv=F(gaussians,1<<240)
    # A certified bound on sum(delta_ideal, delta_sampler).
    # Retain the fractional-bit margin in the ideal bound. Rounding the
    # ideal exponent down first would spuriously lose one whole bit after
    # adding an arbitrarily tiny sampler error (143 -> 142 for main).
    precision=896
    scaled=(tail_exponent_lower-lnprefactorU)*(1<<precision)
    zlo=scaled.numerator//scaled.denominator
    assert zlo>0
    _,ideal_probability_upper=exp_negative_interval(zlo,zlo+1,precision)
    implemented_bound=F(ideal_probability_upper,1<<precision)+finite_tv
    implemented_bits=0
    while implemented_bound<F(1,1<<(implemented_bits+1)):implemented_bits+=1
    with localcontext() as ctx:
        ctx.prec=110
        pi=(D(PL)+D(PU))/2;ln2=Decimal(2).ln()
        VG=D(st*st+s*s*n*phi*(L*V*V+2*V*K+2*K*K+3*d*L*U*U))/(2*pi)
        logideal=D(2*phi*B).ln()/ln2-D(T*T)/(2*(VG+D(VQ))*ln2)
        logtv=D(gaussians).ln()/ln2-240
        logcombined=((logideal*ln2).exp()+(logtv*ln2).exp()).ln()/ln2
        h=D(2*dimension*((1<<160)+1)).ln()/pi
        rhs=1/(2*h+Decimal(2)**(D(15)/2))
        out={
          'preset':p['preset'],'capacity':p['capacity'],'slots':B,'source_columns':source_columns,
          'ciphertext_bytes':p['ciphertext_bytes'],'public_parameters_bytes':(n*3*d*n+n*n+B*n)*phi*6,
          'public_state_bytes':p['counter_bytes']+B*n*phi*6,'public_key_bytes':n*phi*6,
          'secret_key_bytes':(n*phi*(2*K).bit_length()+7)//8,
          'witness_bytes':p['counter_bytes']+1+(3*d*n*L*phi*(2*U).bit_length()+7)//8,
          'registry_record_bytes':p['counter_bytes']+((3**L-1).bit_length()+7)//8+n*phi*6,
          'quantized_coefficients':(3*d*n*L+n+B)*phi,'gaussian_coefficients':gaussians,
          'ring_products':{'keygen':n*n,'internal_node':3*d*n*n,'encryption':3*d*n*n*L+n*n+n*B,'decryption':3*d*n*L+n},
          'security_inequality_lhs':str(D(lhs)),'security_inequality_rhs':str(rhs),
          'ideal_Gaussian_log2_DFR_bound':str(logideal),
          'ideal_DFR_certified_strictly_below':f'2^-{ideal_bits}',
          'finite_sampler_log2_TV_bound':str(logtv),
          'implemented_log2_DFR_bound_in_ideal_random_bit_model':str(logcombined),
          'implemented_DFR_certified_strictly_below':f'2^-{implemented_bits}',
          'fraction_certificates_pass':True,
          'statistical_reduction_log2_term':str((D(L+1)*4/(D(2)**160-1)+D(16*B)/D(2)**160).ln()/ln2),
          'security_estimator':'not run; no new concrete attack-cost or NIST-category claim'
        }
        assert implemented_bits>=143
        return out

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--binary',default=str(ROOT/'build/rbe_cli'));parser.add_argument('--out',default=str(ROOT/'results/parameters.json'));args=parser.parse_args()
    rows=[evaluate(json.loads(subprocess.check_output([args.binary,'params','--preset',name],text=True))) for name in PRESETS]
    matched=rows[1]['ciphertext_bytes'];ind=rows[2]['ciphertext_bytes'];rad=rows[3]['ciphertext_bytes']
    result={'format':1,'precision_digits':110,'rigorous_checks':'outward integer intervals and exact rational sufficient inequalities','sampler_bound_per_coefficient':'2^-240 (ideal random bits, before CSPRNG computational advantage)','instances':rows,'matched_reduction_percent':str(D(100)*D(ind-matched)/D(ind)),'radix_reduction_percent':str(D(100)*D(rad-matched)/D(rad)),'original_KLSS_32bit_reference_bytes':7005188,'original_KLSS_runtime_comparison':False}
    Path(args.out).parent.mkdir(parents=True,exist_ok=True);Path(args.out).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'parameter_instances':len(rows),'all_fraction_certificates_pass':True,'output':Path(args.out).name}))
if __name__=='__main__':main()
