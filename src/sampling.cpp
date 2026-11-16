#include "rbe/rbe.hpp"
#include "rbe/gaussian_tables.hpp"
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
namespace rbe {
  std::string sha256(const Bytes& b) {
    std::array<unsigned char,32> out {
    };
    unsigned len=0;
    require(EVP_Digest(b.data(),b.size(),out.data(),&len,EVP_sha256(),nullptr)==1&&len==32,"SHA256 failed");
    std::ostringstream s;
    s<<std::hex<<std::setfill('0');
    for(auto x:out)s<<std::setw(2)<<static_cast<unsigned>(x);
    return s.str();
  }
  Random::Random(std::optional<std::string> seed) {
    if(seed) {
      std::string s="RBE-ARTIFACT-TEST-ONLY-v1:"+*seed;
      std::array<unsigned char,32> key {
      };
      unsigned len=0;
      require(EVP_Digest(s.data(),s.size(),key.data(),&len,EVP_sha256(),nullptr)==1&&len==32,"test seed hash failed");
      test_=EVP_CIPHER_CTX_new();
      require(test_!=nullptr,"cipher allocation failed");
      std::array<unsigned char,16> iv {
      };
      if(EVP_EncryptInit_ex(test_,EVP_chacha20(),nullptr,key.data(),iv.data())!=1) {
        EVP_CIPHER_CTX_free(test_);
        test_=nullptr;
        throw Error("test stream initialization failed");
      }
      OPENSSL_cleanse(key.data(),key.size());
    }
  }
  Random::~Random() {
    EVP_CIPHER_CTX_free(test_);
    OPENSSL_cleanse(buffer_.data(),buffer_.size());
  }
  void Random::refill() {
    if(test_) {
      require(generated<(1ULL<<36),"test stream limit");
      std::array<unsigned char,65536> zeros {
      };
      int n=0;
      require(EVP_EncryptUpdate(test_,buffer_.data(),&n,zeros.data(),static_cast<int>(zeros.size()))==1&&n==static_cast<int>(buffer_.size()),"test stream failed");
    }
    else require(RAND_priv_bytes(buffer_.data(),static_cast<int>(buffer_.size()))==1,"cryptographic entropy failed");
    pos_=0;
    generated+=buffer_.size();
  }
  void Random::fill(std::uint8_t* out,std::size_t n) {
    while(n) {
      if(pos_==buffer_.size())refill();
      auto k=std::min(n,buffer_.size()-pos_);
      std::memcpy(out,buffer_.data()+pos_,k);
      out+=k;
      n-=k;
      pos_+=k;
      consumed+=k;
    }
  }
  u64 Random::word() {
    std::array<std::uint8_t,8> b {
    };
    fill(b.data(),8);
    u64 r=0;
    for(unsigned i=0; i<8; ++i)r|=static_cast<u64>(b[i])<<(8*i);
    return r;
  }
  bool Random::bit() {
    std::uint8_t b;
    fill(&b,1);
    return (b&1)!=0;
  }
  U256 Random::word256() {
    U256 u;
    for(auto& x:u.limb)x=word();
    return u;
  }
  u64 Random::below(u64 bound) {
    require(bound>0,"empty random interval");
    if(bound==1)return 0;
    unsigned bits=bits_for(bound-1),bytes=(bits+7)/8;
    u64 mask=bits==64?~u64 {
      0
    }
    :(u64 {
      1
    }
    <<bits)-1;
    for(; ; ) {
      std::array<std::uint8_t,8>b {
      };
      fill(b.data(),bytes);
      u64 x=0;
      for(unsigned j=0; j<bytes; ++j)x|=static_cast<u64>(b[j])<<(8*j);
      x&=mask;
      if(x<bound)return x;
      ++rejections;
    }
  }
  u128 Random::below128(u128 bound) {
    require(bound>0,"empty random interval");
    if(bound==1)return 0;
    unsigned bits=0;
    for(u128 x=bound-1; x; x>>=1)++bits;
    unsigned bytes=(bits+7)/8;
    u128 mask=bits==128?~u128 {
      0
    }
    :(u128 {
      1
    }
    <<bits)-1;
    for(; ; ) {
      std::array<std::uint8_t,16>b {
      };
      fill(b.data(),bytes);
      u128 x=0;
      for(unsigned j=0; j<bytes; ++j)x|=static_cast<u128>(b[j])<<(8*j);
      x&=mask;
      if(x<bound)return x;
      ++rejections;
    }
  }
  namespace {
    BigInt ceildiv(const BigInt&a,const BigInt&b) {
      return (a+b-1)/b;
    }
    BigInt big(u128 v) {
      return (BigInt(static_cast<u64>(v>>64))<<64)+static_cast<u64>(v);
    }
    template<std::size_t N>std::size_t cdt(Random& r,const std::array<U256,N>& t) {
      auto u=r.word256();
      return static_cast<std::size_t>(std::upper_bound(t.begin(),t.end(),u)-t.begin());
    }
  }
  Interval exp_negative_interval(const BigInt& zl,const BigInt& zu,unsigned P) {
    require(zl>=0&&zu>=zl&&(P==64||P==384),"invalid exponential interval");
    BigInt S=BigInt(1)<<P;
    unsigned r=0;
    while(zu>((S>>3)<<r))++r;
    BigInt xl=zl>>r,xu=ceildiv(zu,BigInt(1)<<r),lo=S,hi=S,tl=S,tu=S;
    unsigned k=0;
    for(; ; ) {
      ++k;
      tl=tl*xl/(S*k);
      tu=ceildiv(tu*xu,S*k);
      if(k&1) {
        lo-=tu;
        hi-=tl;
      }
      else {
        lo+=tl;
        hi+=tu;
      }
      if(tu<=1) {
        BigInt rem=ceildiv(tu*xu,S*(k+1));
        if((k+1)&1)lo-=rem;
        else hi+=rem;
        break;
      }
      require(k<P+32,"interval convergence failed");
    }
    if(lo<0)lo=0;
    if(hi>S)hi=S;
    for(unsigned j=0; j<r; ++j) {
      lo=lo*lo/S;
      hi=ceildiv(hi*hi,S);
    }
    if(hi>S)hi=S;
    return {
      lo,hi
    };
  }
  Interval acceptance_interval(u64 k,u64 j,u64 t,unsigned P) {
    require(k<=384&&t>=1&&t<=187500000000ULL&&j<t&&(P==64||P==384),"invalid Gaussian rejection proposal");
    static const BigInt PI_LO(tables::pi_lo_hex),PI_HI(tables::pi_hi_hex);
    unsigned shift=tables::precision-P;
    BigInt pl=PI_LO>>shift,pu=ceildiv(PI_HI,BigInt(1)<<shift),num=big(static_cast<u128>(2)*k*t*j+static_cast<u128>(j)*j),den=big(static_cast<u128>(1024)*t*t);
    return exp_negative_interval(pl*num/den,ceildiv(pu*num,den),P);
  }
  U256 as_u256(const BigInt& v) {
    require(v>=0&&v<(BigInt(1)<<256),"256-bit conversion overflow");
    U256 u;
    BigInt mask=(BigInt(1)<<64)-1;
    for(unsigned i=0; i<4; ++i)u.limb[i]=((v>>(64*i))&mask).convert_to<u64>();
    return u;
  }
  bool gaussian_bernoulli(u64 k,u64 j,u64 t,const U256& u,bool* refined) {
    if(refined)*refined=false;
    auto a=acceptance_interval(k,j,t,64);
    BigInt high=u.limb[3];
    if(high+1<=a.lo)return true;
    if(high>=a.hi)return false;
    if(refined)*refined=true;
    auto fine=acceptance_interval(k,j,t,384);
    require(fine.hi-fine.lo<=(BigInt(1)<<32),"Gaussian enclosure width exceeded");
    BigInt threshold=fine.lo>>128;
    if(threshold==(BigInt(1)<<256))return true;
    return u<as_u256(threshold);
  }
  i64 Gaussian::small(u64 s) {
    ++small_samples;
    if(s==32)return static_cast<i64>(cdt(rng_,tables::full32))-384;
    if(s==17)return static_cast<i64>(cdt(rng_,tables::full17))-204;
    throw Error("unsupported CDT width");
  }
  i64 Gaussian::large(u64 s) {
    require(s>=32&&s%32==0&&s<=6000000000000ULL,"unsupported large width");
    ++large_samples;
    u64 t=s/32;
    for(; ; ) {
      ++candidates;
      u64 k=static_cast<u64>(cdt(rng_,tables::half32)),j=rng_.below(t),x=k*t+j;
      bool neg=rng_.bit();
      if(x==0&&neg) {
        ++rejections;
        continue;
      }
      bool refined=false,accept=gaussian_bernoulli(k,j,t,rng_.word256(),&refined);
      refinements+=refined;
      if(!accept) {
        ++rejections;
        continue;
      }
      return neg?-static_cast<i64>(x):static_cast<i64>(x);
    }
  }
  Weights quantizer_weights(u64 a,u64 q,u64 M) {
    require(q>=2&&q<(1ULL<<50)&&M>=2&&M<=q&&a<q,"invalid quantizer input");
    u128 v=static_cast<u128>(M)*a;
    auto j=static_cast<i64>(v/q);
    u64 r=static_cast<u64>(v%q);
    Weights w;
    w.denominator=static_cast<u128>(8)*q*M;
    u128 left=static_cast<u128>(8)*M*(q-r),right=static_cast<u128>(8)*M*r;
    if(2*r<M) {
      u128 t=M-2*r,s=t*t;
      w.k= {
        j-1,j,j+1
      };
      w.w= {
        s,left-2*s,right+s
      };
      w.count=3;
    }
    else if(2*(q-r)<M) {
      u128 t=M-2*(q-r),s=t*t;
      w.k= {
        j,j+1,j+2
      };
      w.w= {
        left+s,right-2*s,s
      };
      w.count=3;
    }
    else {
      w.k= {
        j,j+1,0
      };
      w.w= {
        left,right,0
      };
      w.count=2;
    }
    require(w.w[0]+w.w[1]+w.w[2]==w.denominator,"quantizer mass mismatch");
    return w;
  }
  u64 quantize(u64 a,u64 q,u64 M,Random& rng) {
    auto w=quantizer_weights(a,q,M);
    u128 v=rng.below128(w.denominator);
    for(std::size_t j=0; j<w.count; ++j) {
      if(v<w.w[j])return reduce_signed(w.k[j],M);
      v-=w.w[j];
    }
    throw Error("quantizer selection failed");
  }
}
// namespace rbe
