#include "rbe/rbe.hpp"
#include <algorithm>
#include <sstream>
namespace rbe {
  std::string decimal(u128 x) {
    if(!x)return "0";
    std::string s;
    while(x) {
      s.push_back(static_cast<char>('0'+x%10));
      x/=10;
    }
    std::reverse(s.begin(),s.end());
    return s;
  }
  unsigned Params::identity_bytes()const {
    BigInt a=1;
    for(std::size_t i=0; i<L; ++i)a*=3;
    --a;
    return static_cast<unsigned>((boost::multiprecision::msb(a)+8)/8);
  }
  void Params::validate()const {
    require(phi>=2&&phi<=1024&&(phi&(phi-1))==0,"invalid ring degree");
    require(n>0&&n<=16&&L>0&&L<=512,"invalid dimensions");
    require(q>3&&q<(1ULL<<50)&&(q&1)&&(q-1)%(2*phi)==0,"invalid modulus");
    require(capacity>0&&capacity<=0xffffffffULL,"capacity exceeds counter");
    require(kappa>=2&&kappa<=40&&M()<=q,"invalid transmission precision");
    require(K>0&&K<(1ULL<<30)&&U>0&&U<(1ULL<<30),"invalid short-vector bounds");
    require(sigma==17||sigma==32,"unsupported small Gaussian width");
    require(sigma_tilde>=32&&sigma_tilde%32==0&&sigma_tilde<=6000000000000ULL,"unsupported large Gaussian width");
    require((decomposition==Decomposition::One&&d()==1)||(decomposition!=Decomposition::One&&d()==2),"decomposition width mismatch");
    for(auto g:scales)require(g>0&&!(g&1)&&g<q,"invalid scale");
    if(decomposition==Decomposition::One)require(U>=(q-1+scales[0])/(2*scales[0])&&V>=scales[0]/2,"insufficient one-coordinate bounds");
    if(decomposition==Decomposition::Independent)require(scales[0]<scales[1]&&U>=(q-1+scales[1])/(2*scales[1])&&U>=(scales[1]+scales[0])/(2*scales[0])&&V>=scales[0]/2,"insufficient independent-scale bounds");
    if(decomposition==Decomposition::Radix) {
      require(radix>=2&&radix<=(1ULL<<16)&&!(radix&1)&&digits>=3&&digits<=4&&dropped+2==digits,"invalid radix");
      u128 power=1,residual=0;
      for(unsigned i=0; i<digits; ++i) {
        if(i<dropped)residual+=(radix/2)*power;
        else require(power==scales[i-dropped],"radix/scales mismatch");
        power*=radix;
      }
      require(q<power&&U>=radix/2&&V>=residual,"insufficient radix bounds");
    }
  }
  void Params::check_identity(const Identity& id)const {
    require(id.size()==L&&std::all_of(id.begin(),id.end(),[](char x) {
      return x>='0'&&x<='2';
    }),"identity must contain L ternary digits");
  }
  void Params::check_key(const Vec& y)const {
    require(y.size()==n,"public key rank mismatch");
    for(const auto& a:y) {
      require(a.size()==phi,"public key degree mismatch");
      for(auto x:a)require(x<q,"noncanonical public key coefficient");
    }
  }
  std::vector<std::string> Params::names() {
    return {
      "main","matched","two-independent","two-radix","published-gadget","toy"
    };
  }
  Params Params::get(const std::string& name) {
    Params p;
    p.name=name;
    if(name=="main") {
    }
    else if(name=="matched")p.capacity=(1ULL<<30)-1;
    else if(name=="two-independent") {
      p.capacity=(1ULL<<30)-1;
      p.decomposition=Decomposition::Independent;
      p.scales= {
        1ULL<<26,1ULL<<37
      };
      p.U=1ULL<<10;
      p.V=1ULL<<25;
      p.kappa=26;
      p.sigma_tilde=1500000000000ULL;
    }
    else if(name=="two-radix") {
      p.capacity=(1ULL<<30)-1;
      p.decomposition=Decomposition::Radix;
      p.scales= {
        1ULL<<24,1ULL<<36
      };
      p.radix=1ULL<<12;
      p.digits=4;
      p.dropped=2;
      p.U=1ULL<<11;
      p.V=(1ULL<<23)+(1ULL<<11);
      p.kappa=27;
      p.sigma_tilde=400000000000ULL;
    }
    else if(name=="published-gadget") {
      p.capacity=(1ULL<<30)-1;
      p.decomposition=Decomposition::Radix;
      p.scales= {
        1ULL<<16,1ULL<<32
      };
      p.radix=1ULL<<16;
      p.digits=3;
      p.dropped=1;
      p.U=p.V=1ULL<<15;
      p.kappa=31;
      p.sigma=17;
      p.sigma_tilde=1ULL<<35;
    }
    else if(name=="toy") {
      p.phi=8;
      p.n=2;
      p.L=4;
      p.capacity=16;
    }
    else throw Error("unknown preset: "+name);
    p.validate();
    return p;
  }
  std::string Params::json()const {
    std::ostringstream o;
    o<<"{\n  \"preset\": \""<<name<<"\",\n  \"phi\": "<<phi<<", \"n\": "<<n<<", \"L\": "<<L<<",\n  \"q\": "<<q<<", \"capacity\": "<<capacity<<", \"B\": "<<slots()<<",\n  \"kappa\": "<<kappa<<", \"K\": "<<K<<", \"U\": "<<U<<", \"V\": "<<V<<",\n  \"sigma\": "<<sigma<<", \"sigma_tilde\": "<<sigma_tilde<<",\n  \"scales\": [";
    for(std::size_t i=0; i<d(); ++i) {
      if(i)o<<", ";
      o<<scales[i];
    }
    o<<"],\n  \"decomposition\": \""<<(decomposition==Decomposition::One?"one":decomposition==Decomposition::Independent?"independent":"radix")<<"\", \"radix\": "<<radix<<", \"digits\": "<<digits<<", \"dropped\": "<<dropped<<",\n  \"counter_bytes\": "<<counter_bytes()<<", \"ciphertext_bytes\": "<<ciphertext_bytes()<<",\n  \"security\": \""<<(name=="toy"?"insecure test dimensions":"paper source assumptions; not a fresh security estimate")<<"\"\n}\n";
    return o.str();
  }
  Decomposed decompose(u64 a,const Params& p) {
    require(a<p.q,"noncanonical decomposition input");
    i64 c=centered(a,p.q);
    Decomposed r;
    if(p.decomposition==Decomposition::One) {
      i64 u=-round_div(c,p.scales[0]);
      r= {
        {
          u
        },static_cast<i64>(static_cast<i128>(c)+static_cast<i128>(p.scales[0])*u)
      };
    }
    else if(p.decomposition==Decomposition::Independent) {
      i64 u1=-round_div(c,p.scales[1]);
      i128 z=static_cast<i128>(c)+static_cast<i128>(p.scales[1])*u1;
      i64 u0=-round_div(z,p.scales[0]);
      r= {
        {
          u0,u1
        },static_cast<i64>(z+static_cast<i128>(p.scales[0])*u0)
      };
    }
    else {
      u128 H=0,b=1;
      for(unsigned i=0; i<p.digits; ++i) {
        H+=(p.radix/2)*b;
        b*=p.radix;
      }
      u64 v=static_cast<u64>((a+H)%p.q);
      i128 f=0;
      b=1;
      for(unsigned i=0; i<p.digits; ++i) {
        i64 ai=static_cast<i64>(v%p.radix)-static_cast<i64>(p.radix/2);
        v/=p.radix;
        if(i<p.dropped)f+=static_cast<i128>(b)*ai;
        else r.u.push_back(-ai);
        b*=p.radix;
      }
      r.residual=static_cast<i64>(f);
    }
    i128 relation=c-r.residual;
    for(std::size_t i=0; i<r.u.size(); ++i) {
      require(r.u[i]>=-static_cast<i64>(p.U)&&r.u[i]<=static_cast<i64>(p.U),"quotient bound violated");
      relation+=static_cast<i128>(p.scales[i])*r.u[i];
    }
    require(r.residual>=-static_cast<i64>(p.V)&&r.residual<=static_cast<i64>(p.V),"residual bound violated");
    require(reduce_signed(relation,p.q)==0,"decomposition relation failed");
    return r;
  }
  SVec decompose_label(const Vec& y,const Params& p) {
    p.check_key(y);
    SVec u(p.n*p.d(),SPoly(p.phi));
    for(std::size_t k=0; k<p.n; ++k)for(std::size_t j=0; j<p.phi; ++j) {
      auto a=decompose(y[k][j],p);
      for(std::size_t i=0; i<p.d(); ++i)u[k*p.d()+i][j]=a.u[i];
    }
    return u;
  }
  u64 mul_mod(u64 a,u64 b,u64 q) {
    return q<=0xffffffffULL?(a*b)%q:static_cast<u64>(static_cast<u128>(a)*b%q);
  }
  u64 pow_mod(u64 a,u64 e,u64 q) {
    u64 r=1;
    for(; e; e>>=1,a=mul_mod(a,a,q))if(e&1)r=mul_mod(r,a,q);
    return r;
  }
  bool prime64(u64 q) {
    if(q<2)return false;
    for(u64 p: {
      2ULL,3ULL,5ULL,7ULL,11ULL,13ULL,17ULL,19ULL,23ULL,29ULL,31ULL,37ULL
    }) {
      if(q==p)return true;
      if(q%p==0)return false;
    }
    u64 d=q-1;
    unsigned s=0;
    while(!(d&1)) {
      d>>=1;
      ++s;
    }
    for(u64 a: {
      2ULL,325ULL,9375ULL,28178ULL,450775ULL,9780504ULL,1795265022ULL
    }) {
      if(a%q==0)continue;
      u64 x=pow_mod(a%q,d,q);
      if(x==1||x==q-1)continue;
      bool composite=true;
      for(unsigned r=1; r<s; ++r) {
        x=mul_mod(x,x,q);
        if(x==q-1) {
          composite=false;
          break;
        }
      }
      if(composite)return false;
    }
    return true;
  }
  NTT::NTT(std::size_t size,u64 q):size_(size),q_(q),psi_(0),twist_(size),untwist_(size),reversal_(size) {
    require(size>=2&&size<=1024&&(size&(size-1))==0&&(q-1)%(2*size)==0&&q<(1ULL<<50)&&prime64(q),"invalid NTT parameters");
    for(u64 a=2; a<10000; ++a) {
      auto x=pow_mod(a,(q-1)/(2*size),q);
      if(pow_mod(x,size,q)==q-1) {
        psi_=x;
        break;
      }
    }
    require(psi_!=0,"no primitive root");
    u64 invpsi=pow_mod(psi_,q-2,q),invn=pow_mod(size,q-2,q);
    twist_[0]=1;
    untwist_[0]=invn;
    for(std::size_t i=1; i<size; ++i) {
      twist_[i]=mul_mod(twist_[i-1],psi_,q);
      untwist_[i]=mul_mod(untwist_[i-1],invpsi,q);
    }
    for(std::size_t i=0; i<size; ++i) {
      std::size_t x=i,r=0;
      for(std::size_t j=size; j>1; j>>=1) {
        r=(r<<1)|(x&1);
        x>>=1;
      }
      reversal_[i]=r;
    }
    u64 omega=mul_mod(psi_,psi_,q),invomega=pow_mod(omega,q-2,q);
    for(std::size_t len=2; len<=size; len<<=1) {
      Poly f(len/2,1),b(len/2,1);
      u64 w=pow_mod(omega,size/len,q),wi=pow_mod(invomega,size/len,q);
      for(std::size_t j=1; j<len/2; ++j) {
        f[j]=mul_mod(f[j-1],w,q);
        b[j]=mul_mod(b[j-1],wi,q);
      }
      roots_.push_back(std::move(f));
      iroots_.push_back(std::move(b));
    }
  }
  void NTT::cyclic(Poly& a,bool inverse)const {
    for(std::size_t i=0; i<size_; ++i)if(i<reversal_[i])std::swap(a[i],a[reversal_[i]]);
    std::size_t stage=0;
    for(std::size_t len=2; len<=size_; len<<=1,++stage) {
      const auto& roots=inverse?iroots_[stage]:roots_[stage];
      for(std::size_t start=0; start<size_; start+=len)for(std::size_t j=0; j<len/2; ++j) {
        u64 u=a[start+j],v=mul_mod(a[start+j+len/2],roots[j],q_),s=u+v;
        if(s>=q_)s-=q_;
        a[start+j]=s;
        a[start+j+len/2]=u>=v?u-v:u+q_-v;
      }
    }
  }
  Poly NTT::forward(const Poly& a)const {
    require(a.size()==size_,"NTT degree mismatch");
    Poly b(size_);
    for(std::size_t i=0; i<size_; ++i) {
      require(a[i]<q_,"noncanonical NTT input");
      b[i]=mul_mod(a[i],twist_[i],q_);
    }
    cyclic(b,false);
    return b;
  }
  Poly NTT::forward(const SPoly& a)const {
    require(a.size()==size_,"NTT degree mismatch");
    Poly b(size_);
    for(std::size_t i=0; i<size_; ++i)b[i]=mul_mod(reduce_signed(a[i],q_),twist_[i],q_);
    cyclic(b,false);
    return b;
  }
  Poly NTT::inverse(Poly a)const {
    require(a.size()==size_,"NTT degree mismatch");
    cyclic(a,true);
    for(std::size_t i=0; i<size_; ++i)a[i]=mul_mod(a[i],untwist_[i],q_);
    return a;
  }
  Poly NTT::product(const Poly& a,const Poly& b)const {
    auto x=forward(a),y=forward(b);
    for(std::size_t i=0; i<size_; ++i)x[i]=mul_mod(x[i],y[i],q_);
    return inverse(std::move(x));
  }
  Poly schoolbook(const Poly& a,const Poly& b,u64 q) {
    require(a.size()==b.size()&&a.size()<=1024&&q<(1ULL<<50),"reference product shape");
    std::vector<i128> c(a.size());
    for(std::size_t i=0; i<a.size(); ++i)for(std::size_t j=0; j<b.size(); ++j) {
      i128 x=static_cast<i128>(a[i])*b[j];
      if(i+j<a.size())c[i+j]+=x;
      else c[i+j-a.size()]-=x;
    }
    Poly r(a.size());
    for(std::size_t i=0; i<a.size(); ++i)r[i]=reduce_signed(c[i],q);
    return r;
  }
  CRTDot::CRTDot(std::size_t n):ntt_ {
    NTT(n,998244353),NTT(n,1004535809),NTT(n,469762049)
  }
  {
    u64 a=ntt_[0].modulus(),b=ntt_[1].modulus(),c=ntt_[2].modulus();
    inv12_=pow_mod(a%b,b-2,b);
    inv123_=pow_mod(static_cast<u64>(static_cast<u128>(a)*b%c),c-2,c);
    product_=static_cast<u128>(a)*b*c;
  }
  Poly CRTDot::compute(const Vec& a,const SVec& b,u64 M)const {
    require(a.size()==b.size()&&a.size()<=2000000&&M>=2&&M<=(1ULL<<40)&&(M&(M-1))==0,"CRT dot parameters");
    const auto n=ntt_[0].size();
    u128 bound=0;
    for(std::size_t i=0; i<a.size(); ++i) {
      require(a[i].size()==n&&b[i].size()==n,"CRT degree mismatch");
      u64 ma=0,mb=0;
      for(std::size_t j=0; j<n; ++j) {
        require(a[i][j]<M,"ciphertext coefficient out of range");
        ma=std::max(ma,a[i][j]);
        u64 v=static_cast<u64>(b[i][j]<0?-static_cast<i128>(b[i][j]):b[i][j]);
        require(v<=(1ULL<<40),"CRT multiplier too large");
        mb=std::max(mb,v);
      }
      bound+=static_cast<u128>(n)*ma*mb;
      require(bound<product_/2,"insufficient exact CRT range");
    }
    std::array<Poly,3> residues;
    for(std::size_t z=0; z<3; ++z) {
      const auto& nt=ntt_[z];
      auto p=nt.modulus();
      std::vector<u128> acc(n);
      for(std::size_t i=0; i<a.size(); ++i) {
        Poly x(n);
        for(std::size_t j=0; j<n; ++j)x[j]=a[i][j]%p;
        x=nt.forward(x);
        auto y=nt.forward(b[i]);
        for(std::size_t j=0; j<n; ++j)acc[j]+=static_cast<u128>(x[j])*y[j];
      }
      Poly x(n);
      for(std::size_t j=0; j<n; ++j)x[j]=static_cast<u64>(acc[j]%p);
      residues[z]=nt.inverse(std::move(x));
    }
    u64 p1=ntt_[0].modulus(),p2=ntt_[1].modulus(),p3=ntt_[2].modulus();
    Poly out(n);
    for(std::size_t j=0; j<n; ++j) {
      u64 a1=residues[0][j],t=mul_mod((residues[1][j]+p2-a1%p2)%p2,inv12_,p2);
      u128 x=a1+static_cast<u128>(p1)*t;
      u64 z=mul_mod((residues[2][j]+p3-static_cast<u64>(x%p3))%p3,inv123_,p3);
      x+=static_cast<u128>(p1)*p2*z;
      i128 signed_x=static_cast<i128>(x);
      if(x>product_/2)signed_x-=static_cast<i128>(product_);
      out[j]=reduce_signed(signed_x,M);
    }
    return out;
  }
}
// namespace rbe
