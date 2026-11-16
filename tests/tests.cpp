#include "rbe/rbe.hpp"
#include "rbe/gaussian_tables.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
using namespace rbe;
namespace {
  u64 checks=0,groups=0;
  void check(bool b,std::string_view why) {
    ++checks;
    if(!b)throw Error(std::string(why));
  }
  void rejects(const std::function<void()>& f) {
    bool caught=false;
    try {
      f();
    }
    catch(const std::exception&) {
      caught=true;
    }
    check(caught,"expected rejection");
  }
  void group(const char* s,const std::function<void()>& f) {
    f();
    ++groups;
    std::cout<<"PASS "<<s<<"\n"<<std::flush;
  }
  Message message(const Params& p) {
    Message m(p.phi);
    for(std::size_t i=0; i<p.phi; ++i)m[i]=static_cast<std::uint8_t>((i*13+1)%2);
    return m;
  }
  void parameters() {
    const std::map<std::string,std::size_t> sizes= {
      {
        "main",3742724
      }, {
        "matched",3741636
      }, {
        "two-independent",5691716
      }, {
        "two-radix",5910628
      }, {
        "published-gadget",6786276
      }, {
        "toy",1055
      }
    };
    Random r("decomposition-tests");
    for(const auto& name:Params::names()) {
      auto p=Params::get(name);
      check(p.ciphertext_bytes()==sizes.at(name),"ciphertext size");
      for(unsigned j=0; j<10000; ++j) {
        auto a=r.below(p.q);
        auto v=decompose(a,p);
        i128 sum=a-v.residual;
        for(std::size_t k=0; k<v.u.size(); ++k)sum+=static_cast<i128>(p.scales[k])*v.u[k];
        check(reduce_signed(sum,p.q)==0,"decomposition relation");
      }
      std::set<u64> edges {
        0,1,p.q/2,p.q/2+1,p.q-2,p.q-1
      };
      for(auto g:p.scales)for(i64 z: {
        -2,-1,0,1,2
      }) {
        edges.insert(reduce_signed(static_cast<i128>(g/2)+z,p.q));
        edges.insert(reduce_signed(-static_cast<i128>(g/2)+z,p.q));
      }
      for(auto a:edges) {
        auto d=decompose(a,p);
        check(d.u.size()==p.d(),"edge decomposition");
      }
    }
    auto p=Params::get("main");
    check(p.pp_bytes()==634368&&p.witness_bytes()==2286149&&p.slots()==31,"main serialized sizes");
    p.kappa=63;
    rejects([&] {
      p.validate();
    });
    p=Params::get("main");
    p.capacity=0;
    rejects([&] {
      p.validate();
    });
    rejects([] {
      Params::get("not-a-preset");
    });
    check(round_div(-2,4)==0&&round_div(2,4)==1,"tie breaking");
  }
  void arithmetic() {
    Random r("arithmetic-tests");
    for(u64 q: {
      281474976694273ULL,998244353ULL,1004535809ULL,469762049ULL
    })for(std::size_t n: {
      8U,16U,256U
    }) {
      NTT nt(n,q);
      check(prime64(q)&&pow_mod(nt.psi(),n,q)==q-1,"NTT root");
      for(unsigned rep=0; rep<4; ++rep) {
        Poly a(n),b(n);
        for(auto& x:a)x=r.below(q);
        for(auto& x:b)x=r.below(q);
        check(nt.inverse(nt.forward(a))==a,"NTT inverse");
        check(nt.product(a,b)==schoolbook(a,b,q),"NTT vs independent product");
      }
      Poly a(n),b(n);
      a[n-1]=1;
      b[1]=1;
      auto product=nt.product(a,b);
      check(product[0]==q-1&&std::count(product.begin()+1,product.end(),0)==static_cast<long>(n-1),"negacyclic sign");
    }
    check(!prime64(1)&&!prime64(561)&&!prime64(3215031751ULL)&&prime64(2),"Miller-Rabin");
    for(std::size_t n: {
      8U,256U
    }) {
      CRTDot dot(n);
      for(unsigned rep=0; rep<3; ++rep) {
        u64 M=1ULL<<34;
        Vec a(7,Poly(n));
        SVec b(7,SPoly(n));
        Poly expected(n);
        for(std::size_t i=0; i<a.size(); ++i) {
          Poly bp(n);
          for(std::size_t j=0; j<n; ++j) {
            a[i][j]=r.below(M);
            b[i][j]=static_cast<i64>(r.below(1ULL<<20))-static_cast<i64>(1ULL<<19);
            bp[j]=reduce_signed(b[i][j],M);
          }
          auto prod=schoolbook(a[i],bp,M);
          for(std::size_t j=0; j<n; ++j)expected[j]=(expected[j]+prod[j])%M;
        }
        check(dot.compute(a,b,M)==expected,"exact CRT vs schoolbook");
      }
      Vec a(1,Poly(n,1ULL<<34));
      SVec b(1,SPoly(n,0));
      rejects([&] {
        dot.compute(a,b,1ULL<<34);
      });
    }
  }
  void quantizer() {
    u64 rows=0,pairs=0;
    for(u64 q=2; q<=64; ++q)for(u64 M=2; M<=q; ++M) {
      ++pairs;
      std::vector<u128> marginal(M);
      for(u64 a=0; a<q; ++a) {
        ++rows;
        auto w=quantizer_weights(a,q,M);
        u128 sum=0;
        i128 moment=0;
        u128 second=0;
        for(std::size_t i=0; i<w.count; ++i) {
          sum+=w.w[i];
          i128 e=static_cast<i128>(q)*w.k[i]-static_cast<i128>(M)*a;
          moment+=static_cast<i128>(w.w[i])*e;
          second+=w.w[i]*static_cast<u128>(e*e);
          marginal[reduce_signed(w.k[i],M)]+=w.w[i];
        }
        check(sum==w.denominator,"quantizer mass");
        check(moment==0,"conditional mean");
        check(12*second<=w.denominator*(static_cast<u128>(3)*q*q+static_cast<u128>(M)*M),"quantizer second moment");
      }
      for(auto x:marginal)check(x==static_cast<u128>(8)*q*q,"uniform output marginal");
    }
    check(pairs==2016&&rows==87360,"exhaustive quantizer coverage");
    auto p=Params::get("main");
    Random r("quantizer-main-tests");
    for(unsigned t=0; t<1005; ++t) {
      u64 a=t<5?std::array<u64,5> {
        0,1,p.q/2,p.q-2,p.q-1
      }
      [t]:r.below(p.q);
      auto w=quantizer_weights(a,p.q,p.M());
      BigInt total=0,mean=0,second=0;
      for(std::size_t i=0; i<w.count; ++i) {
        BigInt mass(decimal(w.w[i]));
        BigInt e=BigInt(p.q)*w.k[i]-BigInt(p.M())*a;
        total+=mass;
        mean+=mass*e;
        second+=mass*e*e;
      }
      check(total==BigInt(decimal(w.denominator))&&mean==0,"main quantizer mass/mean");
      check(12*second<=total*(BigInt(3)*p.q*p.q+BigInt(p.M())*p.M()),"main quantizer moment");
      check(quantize(a,p.q,p.M(),r)<p.M(),"quantizer range");
    }
    rejects([] {
      quantizer_weights(3,3,2);
    });
    rejects([] {
      quantizer_weights(0,3,4);
    });
    std::cout<<"coverage quantizer: "<<pairs<<" modulus pairs, "<<rows<<" exhaustive rows, 1005 main-modulus rows\n";
  }
  void gaussian() {
    Random r("sampler-tests");
    Gaussian g(r);
    for(u64 s: {
      17ULL,32ULL
    }) {
      long double sum=0,sq=0;
      for(unsigned i=0; i<30000; ++i) {
        auto x=g.small(s);
        check(x>=-static_cast<i64>(12*s)&&x<=static_cast<i64>(12*s),"Gaussian CDT support");
        sum+=x;
        sq+=static_cast<long double>(x)*x;
      }
      long double mean=sum/30000,var=sq/30000,target=static_cast<long double>(s)*s/(2*acosl(-1));
      check(fabsl(mean)<0.35L&&fabsl(var/target-1)<0.05L,"small Gaussian statistical smoke test");
    }
    long double sum=0,sq=0;
    u64 width=6000000000000ULL;
    for(unsigned i=0; i<3000; ++i) {
      auto x=g.large(width);
      long double v=static_cast<long double>(x)/width;
      sum+=v;
      sq+=v*v;
    }
    check(fabsl(sum/3000)<0.04L&&fabsl(sq/3000-1/(2*acosl(-1)))<0.025L,"large Gaussian statistical smoke test");
    check(g.candidates>=g.large_samples,"rejection accounting");
    u64 k=1,t=187500000000ULL,j=t/2;
    auto fine=acceptance_interval(k,j,t,384);
    BigInt threshold=fine.lo>>128;
    bool refined=false;
    check(gaussian_bernoulli(k,j,t,as_u256(threshold-1),&refined)&&refined,"forced fine acceptance branch");
    check(!gaussian_bernoulli(k,j,t,as_u256(threshold),&refined)&&refined,"forced fine rejection branch");
    check(gaussian_bernoulli(0,0,t,U256 {
      {
        ~u64 {
          0
        },~u64 {
          0
        },~u64 {
          0
        },~u64 {
          0
        }
      }
    }),"accept probability one");
    rejects([&] {
      g.small(33);
    });
    rejects([&] {
      g.large(33);
    });
    for(unsigned P: {
      64U,384U
    })for(u64 kk: {
      0ULL,32ULL,384ULL
    })for(u64 jj:std::array<u64,3> {
      0,t/2,t-1
    }) {
      auto a=acceptance_interval(kk,jj,t,P);
      check(a.lo>=0&&a.hi>=a.lo&&a.hi<=(BigInt(1)<<P),"certified acceptance interval");
      if(P==384)check(a.hi-a.lo<=(BigInt(1)<<32),"fine interval precision budget");
    }
  }
  void encoding() {
    Random r("encoding-tests");
    for(unsigned bits=1; bits<=50; ++bits)for(std::size_t count: {
      0U,1U,2U,17U,257U
    }) {
      std::vector<u64> v(count);
      for(auto& x:v)x=r.below(1ULL<<bits);
      auto b=pack_values(v,bits);
      check(unpack_values(b,count,bits)==v,"bitpacking roundtrip");
      if(!b.empty()) {
        auto truncated=b;
        truncated.pop_back();
        rejects([&] {
          unpack_values(truncated,count,bits);
        });
        if(count*bits%8) {
          b.back()|=0x80;
          rejects([&] {
            unpack_values(b,count,bits);
          });
        }
      }
    }
    check(sha256( {
    })=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","SHA256 KAT");
    rejects([] {
      pack_values( {
        256
      },8);
    });
    auto p=Params::get("toy");
    Engine e(Engine::setup(p,r));
    auto k=e.keygen(r);
    check(decode_pp(encode_pp(e.pp()),p).A1c==e.pp().A1c,"PP encoding");
    check(decode_pk(encode_pk(k.public_key,p),p)==k.public_key,"PK encoding");
    check(decode_sk(encode_sk(k.secret_key,p),p)==k.secret_key,"SK encoding");
    auto invalid=encode_sk(k.secret_key,p);
    invalid[0]=255;
    invalid[1]=255;
    invalid[2]|=1;
    rejects([&] {
      decode_sk(invalid,p);
    });
    auto pk=encode_pk(k.public_key,p);
    std::fill(pk.begin(),pk.begin()+p.q_bytes(),255);
    rejects([&] {
      decode_pk(pk,p);
    });
    auto ppb=encode_pp(e.pp());
    ppb.push_back(0);
    rejects([&] {
      decode_pp(ppb,p);
    });
  }
  void registry() {
    auto p=Params::get("toy");
    Random rng("registry-tests");
    Engine e(Engine::setup(p,rng));
    Registry reg(e,true),replay(e,false);
    auto mu=message(p);
    std::vector<KeyPair> keys;
    std::vector<Witness> historical;
    std::vector<Ciphertext> oldcts;
    unsigned changes=0;
    std::optional<Witness> previous;
    for(u64 i=0; i<16; ++i) {
      auto k=e.keygen(rng);
      auto id=identity_counter(p,i);
      reg.register_key(id,k.public_key);
      replay.register_key(id,k.public_key);
      keys.push_back(k);
      reg.verify_invariants();
      check(encode_state(reg.state(),p)==encode_state(replay.state(),p),"registry replay equivalence");
      auto w=reg.witness(identity_counter(p,0));
      if(previous&&*previous!=w)++changes;
      previous=w;
      historical.push_back(w);
      auto ct=e.encrypt(reg.state(),identity_counter(p,0),mu,rng);
      oldcts.push_back(ct);
      check(e.decrypt(keys[0].secret_key,w,ct)==mu,"full registry roundtrip");
      check(decode_witness(encode_witness(w,p),p)==w,"witness encoding");
      check(e.decrypt(keys[0].secret_key,decode_witness(encode_witness(w,p),p),decode_ct(encode_ct(ct,p),p))==mu,"serialized roundtrip");
    }
    check(changes==4&&reg.witness(identity_counter(p,0)).slot==4,"exact power-of-two capacity boundary");
    for(u64 v=1; v<=16; ++v) {
      auto w=replay.witness(identity_counter(p,0),v);
      check(w==historical[v-1],"historical witness stable");
      check(e.decrypt(keys[0].secret_key,w,oldcts[v-1])==mu,"historical decryption");
      check(encode_state(reg.state_at(v),p)==encode_state(replay.state_at(v),p),"historical state replay");
    }
    auto state=encode_state(reg.state(),p);
    rejects([&] {
      reg.register_key(identity_counter(p,16),keys[0].public_key);
    });
    check(state==encode_state(reg.state(),p),"capacity rejection nonmutating");
    rejects([&] {
      reg.witness(identity_counter(p,0),17);
    });
    auto log=encode_log(reg,p);
    Registry fromlog(e);
    replay_log(log,fromlog,p);
    check(encode_state(fromlog.state(),p)==state,"serialized log replay");
    auto badlog=log;
    badlog.pop_back();
    Registry empty(e);
    rejects([&] {
      replay_log(badlog,empty,p);
    });
    check(empty.version()==0,"invalid log rejected before replay");
    Registry adversarial(e);
    auto kid=e.keygen(rng);
    adversarial.register_key(identity_counter(p,0),e.pp().terminators[0]);
    adversarial.register_key(identity_counter(p,1),kid.public_key);
    adversarial.verify_invariants();
    auto w=adversarial.witness(identity_counter(p,1));
    auto ct=e.encrypt(adversarial.state(),identity_counter(p,1),mu,rng);
    check(e.decrypt(kid.secret_key,w,ct)==mu,"terminator-equal malicious public key");
    auto before=encode_state(adversarial.state(),p);
    rejects([&] {
      adversarial.register_key(identity_counter(p,1),kid.public_key);
    });
    rejects([&] {
      adversarial.register_key("9",kid.public_key);
    });
    auto malformed=kid.public_key;
    malformed[0][0]=p.q;
    rejects([&] {
      adversarial.register_key(identity_counter(p,2),malformed);
    });
    check(before==encode_state(adversarial.state(),p),"invalid registration nonmutating");
    auto unregistered=e.encrypt(adversarial.state(),identity_counter(p,2),mu,rng);
    check(encode_ct(unregistered,p).size()==p.ciphertext_bytes(),"absent-identity encryption");
    rejects([&] {
      adversarial.witness(identity_counter(p,2));
    });
    auto b=encode_ct(ct,p);
    for(unsigned i=0; i<20; ++i) {
      auto bad=b;
      bad.resize(static_cast<std::size_t>(rng.below(b.size())));
      rejects([&] {
        decode_ct(bad,p);
      });
    }
    auto invalidw=w;
    invalidw.created=ct.version+1;
    rejects([&] {
      e.decrypt(kid.secret_key,invalidw,ct);
    });
    auto wrongx=kid.secret_key;
    wrongx[0][0]=static_cast<i64>(p.K)+1;
    rejects([&] {
      e.decrypt(wrongx,w,ct);
    });
  }
  void full(const std::string& name) {
    auto p=Params::get(name);
    Random rng("full-parameter-"+name);
    Engine e(Engine::setup(p,rng));
    auto k=e.keygen(rng);
    Registry reg(e);
    auto id=identity_counter(p,0);
    reg.register_key(id,k.public_key);
    auto mu=message(p);
    auto w=reg.witness(id);
    EncryptStats stats;
    auto ct=e.encrypt(reg.state(),id,mu,rng,&stats);
    auto cb=encode_ct(ct,p);
    check(cb.size()==p.ciphertext_bytes(),"main exact ciphertext bytes");
    check(e.decrypt(k.secret_key,w,ct)==mu,"full-parameter decryption");
    check(e.decrypt(decode_sk(encode_sk(k.secret_key,p),p),decode_witness(encode_witness(w,p),p),decode_ct(cb,p))==mu,"full serialized decryption");
    check(stats.quantized_coefficients==p.ciphertext_polys()*p.phi,"quantizer operation count");
    check(stats.gaussian_samples==((p.L+1)*p.n+p.header_polys()+p.slots())*p.phi,"Gaussian operation count");
    std::cout<<"KAT "<<name<<" pp "<<sha256(encode_pp(e.pp()))<<" ct "<<sha256(cb)<<"\n";
    if(name=="main") {
      auto k2=e.keygen(rng);
      reg.register_key(identity_counter(p,1),k2.public_key);
      auto w2=reg.witness(id);
      check(w2!=w&&w2.slot==1&&reg.witness(id,1)==w,"main historical replay after actual merge");
      check(e.decrypt(k.secret_key,reg.witness(id,1),ct)==mu,"main historical decryption after merge");
      auto ct2=e.encrypt(reg.state(),id,mu,rng);
      check(e.decrypt(k.secret_key,w2,ct2)==mu,"main merge roundtrip");
      reg.verify_invariants();
    }
  }
}
int main(int argc,char** argv) {
  try {
    require(argc==2,"use --quick, --main, --controls, or --all");
    std::string mode=argv[1];
    require(mode=="--quick"||mode=="--main"||mode=="--controls"||mode=="--all","unknown test mode");
    auto start=std::chrono::steady_clock::now();
    if(mode=="--quick"||mode=="--all") {
      group("parameters and decompositions",parameters);
      group("NTT and exact CRT arithmetic",arithmetic);
      group("exact quantizer",quantizer);
      group("finite Gaussian sampling",gaussian);
      group("canonical encodings",encoding);
      group("registration, historical snapshots and malformed inputs",registry);
    }
    if(mode=="--main"||mode=="--all")group("main full parameters",[] {
      full("main");
    });
    if(mode=="--controls"||mode=="--all")for(const auto& name: {
      "matched","two-independent","two-radix","published-gadget"
    })group(name,[&] {
      full(name);
    });
    double elapsed=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
    std::cout<<"PASS TOTAL groups="<<groups<<" assertions="<<checks<<" seconds="<<elapsed<<"\n";
    return 0;
  }
  catch(const std::exception& e) {
    std::cerr<<"FAIL after "<<checks<<" checks: "<<e.what()<<'\n';
    return 1;
  }
}
