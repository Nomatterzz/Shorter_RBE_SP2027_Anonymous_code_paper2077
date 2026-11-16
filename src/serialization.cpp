#include "rbe/rbe.hpp"
#include <fstream>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
namespace rbe {
  namespace {
    void push_uint(Bytes& b,u64 x,unsigned n) {
      for(unsigned i=0; i<n; ++i)b.push_back(static_cast<std::uint8_t>(x>>(8*i)));
      require(n==8||(x>>(8*n))==0,"integer encoding overflow");
    }
    u64 get_uint(const Bytes& b,std::size_t& at,unsigned n) {
      require(at+n<=b.size(),"truncated encoding");
      u64 x=0;
      for(unsigned i=0; i<n; ++i)x|=static_cast<u64>(b[at++])<<(8*i);
      return x;
    }
    void push_vec(Bytes& b,const Vec& v,const Params& p) {
      p.check_key(v);
      for(const auto& a:v)for(auto x:a)push_uint(b,x,p.q_bytes());
    }
    Vec get_vec(const Bytes& b,std::size_t& at,const Params& p) {
      Vec v(p.n,Poly(p.phi));
      for(auto& a:v)for(auto& x:a) {
        x=get_uint(b,at,p.q_bytes());
        require(x<p.q,"noncanonical ring coefficient");
      }
      return v;
    }
    Bytes encode_signed(const SVec& a,std::size_t count,const Params& p,u64 bound,unsigned bits) {
      require(a.size()==count,"signed encoding shape");
      std::vector<u64> v;
      v.reserve(count*p.phi);
      for(const auto& x:a) {
        require(x.size()==p.phi,"signed encoding degree");
        for(auto z:x) {
          require(z>=-static_cast<i64>(bound)&&z<=static_cast<i64>(bound),"signed encoding bound");
          v.push_back(static_cast<u64>(z+static_cast<i64>(bound)));
        }
      }
      return pack_values(v,bits);
    }
    SVec decode_signed(const Bytes& b,std::size_t count,const Params& p,u64 bound,unsigned bits) {
      auto v=unpack_values(b,count*p.phi,bits);
      SVec a(count,SPoly(p.phi));
      std::size_t j=0;
      for(auto& x:a)for(auto& z:x) {
        require(v[j]<=2*bound,"reserved signed encoding");
        z=static_cast<i64>(v[j++])-static_cast<i64>(bound);
      }
      return a;
    }
    void append(Bytes& a,const Bytes& b) {
      a.insert(a.end(),b.begin(),b.end());
    }
  }
  Bytes pack_values(const std::vector<u64>& values,unsigned bits) {
    require(bits>=1&&bits<=50&&values.size()<=(1ULL<<30)/bits,"bit packing dimensions");
    Bytes out;
    out.reserve((values.size()*bits+7)/8);
    u128 acc=0;
    unsigned used=0;
    for(auto x:values) {
      require(x<(1ULL<<bits),"packing overflow");
      acc|=static_cast<u128>(x)<<used;
      used+=bits;
      while(used>=8) {
        out.push_back(static_cast<std::uint8_t>(acc));
        acc>>=8;
        used-=8;
      }
    }
    if(used)out.push_back(static_cast<std::uint8_t>(acc));
    return out;
  }
  std::vector<u64> unpack_values(const Bytes& in,std::size_t count,unsigned bits) {
    require(bits>=1&&bits<=50&&count<=(1ULL<<30)/bits&&in.size()==(count*bits+7)/8,"incorrect packed length");
    std::vector<u64> out;
    out.reserve(count);
    u128 acc=0;
    unsigned used=0;
    std::size_t at=0;
    u64 mask=(1ULL<<bits)-1;
    for(std::size_t i=0; i<count; ++i) {
      while(used<bits) {
        acc|=static_cast<u128>(in[at++])<<used;
        used+=8;
      }
      out.push_back(static_cast<u64>(acc)&mask);
      acc>>=bits;
      used-=bits;
    }
    require(acc==0,"nonzero padding bits");
    return out;
  }
  Bytes encode_pp(const PublicParameters& pp) {
    const auto& p=pp.p;
    p.validate();
    Bytes out;
    out.reserve(p.pp_bytes());
    require(pp.A1c.size()==p.n&&pp.B.size()==p.n&&pp.terminators.size()==p.slots(),"parameter shape");
    for(const auto& row:pp.A1c) {
      require(row.size()==p.width(),"A width");
      for(const auto& a:row) {
        require(a.size()==p.phi,"A degree");
        for(auto x:a) {
          require(x<p.q,"A coefficient");
          push_uint(out,x,p.q_bytes());
        }
      }
    }
    for(const auto& row:pp.B)push_vec(out,row,p);
    for(const auto& t:pp.terminators)push_vec(out,t,p);
    return out;
  }
  PublicParameters decode_pp(const Bytes& b,const Params& p) {
    p.validate();
    require(b.size()==p.pp_bytes(),"parameter encoding length");
    PublicParameters pp;
    pp.p=p;
    std::size_t at=0;
    pp.A1c=Matrix(p.n,Vec(p.width(),Poly(p.phi)));
    for(auto& row:pp.A1c)for(auto& a:row)for(auto& x:a) {
      x=get_uint(b,at,p.q_bytes());
      require(x<p.q,"noncanonical A");
    }
    for(std::size_t i=0; i<p.n; ++i)pp.B.push_back(get_vec(b,at,p));
    for(std::size_t i=0; i<p.slots(); ++i)pp.terminators.push_back(get_vec(b,at,p));
    return pp;
  }
  Bytes encode_pk(const Vec& y,const Params& p) {
    Bytes b;
    push_vec(b,y,p);
    return b;
  }
  Vec decode_pk(const Bytes& b,const Params& p) {
    require(b.size()==p.n*p.phi*p.q_bytes(),"public key length");
    std::size_t at=0;
    return get_vec(b,at,p);
  }
  Bytes encode_sk(const SVec& x,const Params& p) {
    return encode_signed(x,p.n,p,p.K,p.secret_bits());
  }
  SVec decode_sk(const Bytes& b,const Params& p) {
    return decode_signed(b,p.n,p,p.K,p.secret_bits());
  }
  Bytes encode_state(const State& s,const Params& p) {
    require(s.version<=p.capacity&&s.roots.size()==p.slots(),"state shape");
    Bytes b;
    push_uint(b,s.version,p.counter_bytes());
    for(const auto& y:s.roots)push_vec(b,y,p);
    return b;
  }
  State decode_state(const Bytes& b,const Params& p) {
    require(b.size()==p.counter_bytes()+p.slots()*p.n*p.phi*p.q_bytes(),"state length");
    std::size_t at=0;
    State s;
    s.version=get_uint(b,at,p.counter_bytes());
    require(s.version<=p.capacity,"state version");
    for(std::size_t i=0; i<p.slots(); ++i)s.roots.push_back(get_vec(b,at,p));
    return s;
  }
  Bytes encode_witness(const Witness& w,const Params& p) {
    require(w.created>0&&w.created<=p.capacity&&w.slot<p.slots(),"witness metadata");
    Bytes b;
    push_uint(b,w.created,p.counter_bytes());
    push_uint(b,w.slot,1);
    append(b,encode_signed(w.openings,p.L*p.width(),p,p.U,p.witness_bits()));
    return b;
  }
  Witness decode_witness(const Bytes& b,const Params& p) {
    require(b.size()==p.witness_bytes(),"witness length");
    std::size_t at=0;
    Witness w;
    w.created=get_uint(b,at,p.counter_bytes());
    w.slot=static_cast<std::size_t>(get_uint(b,at,1));
    require(w.created>0&&w.created<=p.capacity&&w.slot<p.slots(),"witness metadata");
    w.openings=decode_signed(Bytes(b.begin()+static_cast<std::ptrdiff_t>(at),b.end()),p.L*p.width(),p,p.U,p.witness_bits());
    return w;
  }
  Bytes encode_ct(const Ciphertext& c,const Params& p) {
    require(c.version<=p.capacity&&c.components.size()==p.ciphertext_polys(),"ciphertext shape");
    Bytes b;
    push_uint(b,c.version,p.counter_bytes());
    std::vector<u64> v;
    v.reserve(p.ciphertext_polys()*p.phi);
    for(const auto& a:c.components) {
      require(a.size()==p.phi,"ciphertext degree");
      for(auto x:a) {
        require(x<p.M(),"ciphertext range");
        v.push_back(x);
      }
    }
    append(b,pack_values(v,p.kappa));
    return b;
  }
  Ciphertext decode_ct(const Bytes& b,const Params& p) {
    require(b.size()==p.ciphertext_bytes(),"ciphertext length");
    std::size_t at=0;
    Ciphertext c;
    c.version=get_uint(b,at,p.counter_bytes());
    require(c.version<=p.capacity,"ciphertext version");
    auto v=unpack_values(Bytes(b.begin()+static_cast<std::ptrdiff_t>(at),b.end()),p.ciphertext_polys()*p.phi,p.kappa);
    at=0;
    c.components=Vec(p.ciphertext_polys(),Poly(p.phi));
    for(auto& a:c.components)for(auto& x:a)x=v[at++];
    return c;
  }
  Bytes encode_message(const Message& m,const Params& p) {
    require(m.size()==p.phi,"message length");
    std::vector<u64> v(m.begin(),m.end());
    return pack_values(v,1);
  }
  Message decode_message(const Bytes& b,const Params& p) {
    auto v=unpack_values(b,p.phi,1);
    return Message(v.begin(),v.end());
  }
  Bytes encode_log(const Registry& r,const Params& p) {
    Bytes out;
    u64 v=0;
    for(const auto& record:r.log()) {
      push_uint(out,++v,p.counter_bytes());
      BigInt x=0;
      for(auto c:record->id)x=3*x+(c-'0');
      for(unsigned j=0; j<p.identity_bytes(); ++j) {
        out.push_back((x&255).convert_to<std::uint8_t>());
        x>>=8;
      }
      push_vec(out,record->key,p);
    }
    return out;
  }
  void replay_log(const Bytes& bytes,Registry& r,const Params& p) {
    require(r.version()==0,"log replay requires empty registry");
    std::size_t record_size=p.counter_bytes()+p.identity_bytes()+p.n*p.phi*p.q_bytes();
    require(bytes.size()%record_size==0&&bytes.size()/record_size<=p.capacity,"log length");
    std::vector<Record> records;
    std::unordered_set<Identity> ids;
    std::size_t at=0;
    while(at<bytes.size()) {
      u64 v=get_uint(bytes,at,p.counter_bytes());
      require(v==records.size()+1,"log counter sequence");
      BigInt x=0;
      for(unsigned j=0; j<p.identity_bytes(); ++j)x+=BigInt(bytes[at++])<<(8*j);
      Identity id(p.L,'0');
      for(std::size_t j=p.L; j>0; --j) {
        id[j-1]=static_cast<char>('0'+(x%3).convert_to<unsigned>());
        x/=3;
      }
      require(x==0&&ids.insert(id).second,"invalid or duplicate log identity");
      records.push_back( {
        id,get_vec(bytes,at,p)
      });
    }
    for(const auto& record:records)r.register_key(record.id,record.key);
  }
  Bytes read_file(const std::filesystem::path& path,std::size_t limit) {
    std::ifstream in(path,std::ios::binary|std::ios::ate);
    require(in.good(),"cannot open input file");
    auto end=in.tellg();
    require(end>=0&&static_cast<u64>(end)<=limit,"input too large");
    Bytes b(static_cast<std::size_t>(end));
    in.seekg(0);
    if(!b.empty())in.read(reinterpret_cast<char*>(b.data()),static_cast<std::streamsize>(b.size()));
    require(in.good(),"input read failed");
    return b;
  }
  void write_file(const std::filesystem::path& path,const Bytes& data,bool secret) {
    auto parent=path.parent_path();
    if(!parent.empty())std::filesystem::create_directories(parent);
    std::string tmpl=path.string()+".tmp-XXXXXX";
    std::vector<char> name(tmpl.begin(),tmpl.end());
    name.push_back(0);
    int fd=mkstemp(name.data());
    require(fd>=0,"cannot create output temporary file");
    bool closed=false;
    try {
      require(fchmod(fd,secret?0600:0644)==0,"cannot set file permissions");
      std::size_t at=0;
      while(at<data.size()) {
        ssize_t n=write(fd,data.data()+at,data.size()-at);
        if(n<0&&errno==EINTR)continue;
        require(n>0,"output write failed");
        at+=static_cast<std::size_t>(n);
      }
      require(fsync(fd)==0,"output sync failed");
      require(close(fd)==0,"output close failed");
      closed=true;
      require(rename(name.data(),path.c_str())==0,"output rename failed");
    }
    catch(...) {
      if(!closed)close(fd);
      unlink(name.data());
      throw;
    }
  }
}
// namespace rbe
