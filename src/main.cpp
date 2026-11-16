#include "rbe/rbe.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <map>
#include <set>
#include <iomanip>
#include <sys/resource.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>
using namespace rbe;
namespace {
  using Clock=std::chrono::steady_clock;
  double ms(Clock::time_point a,Clock::time_point b) {
    return std::chrono::duration<double,std::milli>(b-a).count();
  }
  std::string quote(const std::string& s) {
    std::string r="\"";
    for(unsigned char c:s) {
      if(c=='"'||c=='\\') {
        r+='\\';
        r+=static_cast<char>(c);
      }
      else if(c>=32)r+=static_cast<char>(c);
      else throw Error("control character in JSON string");
    }
    return r+'"';
  }
  std::string text(const Bytes& b) {
    return {
      b.begin(),b.end()
    };
  }
  void save_text(const std::filesystem::path& p,const std::string& s) {
    write_file(p,Bytes(s.begin(),s.end()));
  }
  struct Args {
    std::string command;
    std::map<std::string,std::string> options;
    Args(int argc,char** argv) {
      require(argc>=2,"use rbe_cli help");
      command=argv[1];
      for(int i=2; i<argc; i+=2) {
        require(i+1<argc,"option needs a value");
        std::string k=argv[i];
        require(k.starts_with("--")&&options.emplace(k.substr(2),argv[i+1]).second,"invalid or repeated option");
      }
    }
    std::string get(const std::string& k,const std::string& fallback="")const {
      auto it=options.find(k);
      return it==options.end()?fallback:it->second;
    }
    std::string need(const std::string& k)const {
      auto s=get(k);
      require(!s.empty(),"missing required option --"+k);
      return s;
    }
    void allow(std::initializer_list<std::string> keys)const {
      std::set<std::string> legal(keys);
      for(const auto& [k,v]:options) {
        (void)v;
        require(legal.contains(k),"unknown option --"+k);
      }
    }
    std::optional<std::string> seed()const {
      auto it=options.find("test-seed");
      if(it==options.end())return {
      };
      std::cerr<<"WARNING: deterministic TEST-ONLY randomness. Never use these keys for confidentiality.\n";
      return it->second;
    }
  };
  u64 integer(const std::string& s) {
    require(!s.empty()&&std::all_of(s.begin(),s.end(),[](char c) {
      return c>='0'&&c<='9';
    }),"expected unsigned decimal integer");
    std::size_t at=0;
    u64 x=std::stoull(s,&at);
    require(at==s.size(),"invalid number");
    return x;
  }
  struct Lock {
    int fd=-1;
    explicit Lock(const std::filesystem::path& path) {
      fd=open(path.c_str(),O_CREAT|O_RDWR,0600);
      require(fd>=0,"cannot open registry lock");
      if(flock(fd,LOCK_EX)<0) {
        close(fd);
        fd=-1;
        throw Error("cannot lock registry");
      }
    }
    ~Lock() {
      if(fd>=0) {
        flock(fd,LOCK_UN);
        close(fd);
      }
    }
  };
  Params load_params(const std::filesystem::path& dir) {
    auto name=text(read_file(dir/"preset.txt",100));
    while(!name.empty()&&(name.back()=='\n'||name.back()=='\r'))name.pop_back();
    return Params::get(name);
  }
  Engine load_engine(const std::filesystem::path& dir) {
    auto p=load_params(dir);
    return Engine(decode_pp(read_file(dir/"parameters.bin"),p));
  }
  void load_registry(const std::filesystem::path& dir,Registry& reg,const Params& p) {
    replay_log(read_file(dir/"registry.log"),reg,p);
  }
  void require_new(const std::filesystem::path& dir) {
    require(!std::filesystem::exists(dir)||std::filesystem::is_empty(dir),"output directory must be new or empty");
    std::filesystem::create_directories(dir);
  }
  Message random_message(const Params& p,Random& r) {
    Message m(p.phi);
    for(auto& b:m)b=static_cast<std::uint8_t>(r.bit());
    return m;
  }
  void demo(const Args& a) {
    a.allow( {
      "preset","out","test-seed"
    });
    auto p=Params::get(a.get("preset","main"));
    auto out=std::filesystem::path(a.need("out"));
    require_new(out);
    Random random(a.seed());
    auto pp=Engine::setup(p,random);
    Engine e(pp);
    Registry reg(e);
    auto k=e.keygen(random);
    auto id=identity_counter(p,0);
    reg.register_key(id,k.public_key);
    auto oldstate=reg.state();
    auto oldwit=reg.witness(id);
    auto mu=random_message(p,random);
    auto oldct=e.encrypt(oldstate,id,mu,random);
    auto k2=e.keygen(random);
    reg.register_key(identity_counter(p,1),k2.public_key);
    auto k3=e.keygen(random);
    reg.register_key(identity_counter(p,2),k3.public_key);
    auto w=reg.witness(id);
    EncryptStats stats;
    auto ct=e.encrypt(reg.state(),id,mu,random,&stats);
    reg.verify_invariants();
    require(reg.witness(id,1)==oldwit,"historical witness replay failed");
    require(e.decrypt(k.secret_key,w,ct)==mu&&e.decrypt(k.secret_key,oldwit,oldct)==mu,"demo decryption failed");
    save_text(out/"params.json",p.json());
    save_text(out/"preset.txt",p.name+"\n");
    save_text(out/"identity.txt",id+"\n");
    write_file(out/"parameters.bin",encode_pp(pp));
    write_file(out/"state.bin",encode_state(reg.state(),p));
    write_file(out/"registry.log",encode_log(reg,p));
    write_file(out/"public.key",encode_pk(k.public_key,p));
    write_file(out/"secret.key",encode_sk(k.secret_key,p),true);
    write_file(out/"witness.bin",encode_witness(w,p));
    write_file(out/"ciphertext.bin",encode_ct(ct,p));
    write_file(out/"message.bin",encode_message(mu,p));
    write_file(out/"decrypted.bin",encode_message(e.decrypt(k.secret_key,w,ct),p));
    write_file(out/"historical-state.bin",encode_state(oldstate,p));
    write_file(out/"historical-witness.bin",encode_witness(oldwit,p));
    write_file(out/"historical-ciphertext.bin",encode_ct(oldct,p));
    std::cout<<"{\"preset\": "<<quote(p.name)<<", \"ciphertext_bytes\": "<<encode_ct(ct,p).size()<<", \"historical_replay\": true, \"roundtrip\": true, \"gaussian_samples\": "<<stats.gaussian_samples<<", \"quantized_coefficients\": "<<stats.quantized_coefficients<<"}\n";
  }
  void benchmark(const Args& a) {
    a.allow( {
      "preset","users","iterations","out","test-seed"
    });
    auto p=Params::get(a.get("preset","main"));
    u64 users=integer(a.get("users","4")),iterations=integer(a.get("iterations","3"));
    require(users>0&&users<=std::min<u64>(p.capacity,4096)&&iterations>0&&iterations<=1000,"benchmark workload limit");
    auto seed=a.seed();
    Random random(seed);
    auto t0=Clock::now();
    auto pp=Engine::setup(p,random);
    auto t1=Clock::now();
    Engine e(pp);
    auto t2=Clock::now();
    auto ppbytes=encode_pp(pp);
    auto t3=Clock::now();
    std::ostringstream out;
    out<<std::setprecision(12);
    out<<"{\n \"format\": 1, \"preset\": "<<quote(p.name)<<", \"actual_registered_users\": "<<users<<", \"capacity\": "<<p.capacity<<", \"iterations\": "<<iterations<<",\n \"randomness\": "<<quote(seed?"TEST-ONLY deterministic":"OpenSSL RAND_priv_bytes")<<",\n \"compiler\": "<<quote(__VERSION__)<<", \"openssl_runtime\": "<<quote(OpenSSL_version(OPENSSL_VERSION))<<",\n \"comparison_scope\": \"same-backend controls, not upstream KLSS timings\",\n \"setup_ms\": "<<ms(t0,t1)<<", \"public_preparation_ms\": "<<ms(t1,t2)<<", \"pp_serialization_ms\": "<<ms(t2,t3)<<", \"pp_bytes\": "<<ppbytes.size()<<",\n \"runs\": [\n";
    for(u64 trial=0; trial<iterations; ++trial) {
      Registry reg(e);
      std::vector<KeyPair> keys;
      std::vector<Identity> ids;
      auto begin=Clock::now();
      for(u64 i=0; i<users; ++i)keys.push_back(e.keygen(random));
      auto keyend=Clock::now();
      for(u64 i=0; i<users; ++i)ids.push_back(p.L>=162?identity_label(p,"benchmark-user-"+std::to_string(i)):identity_counter(p,i));
      std::vector<double> registrations;
      auto regstart=Clock::now();
      for(u64 i=0; i<users; ++i) {
        auto s=Clock::now();
        reg.register_key(ids[i],keys[i].public_key);
        registrations.push_back(ms(s,Clock::now()));
      }
      auto regend=Clock::now();
      auto witness=reg.witness(ids[0]);
      auto wend=Clock::now();
      auto wb=encode_witness(witness,p);
      auto wsend=Clock::now();
      auto message=random_message(p,random);
      EncryptStats stats;
      auto encstart=Clock::now();
      auto ct=e.encrypt(reg.state(),ids[0],message,random,&stats);
      auto encend=Clock::now();
      auto bytes=encode_ct(ct,p);
      auto serend=Clock::now();
      auto parsed=decode_ct(bytes,p);
      auto parseend=Clock::now();
      auto decrypted=e.decrypt(keys[0].secret_key,witness,parsed);
      auto decend=Clock::now();
      require(decrypted==message,"benchmark correctness failed");
      auto log=encode_log(reg,p);
      auto st=encode_state(reg.state(),p);
      struct rusage usage {
      };
      require(getrusage(RUSAGE_SELF,&usage)==0,"getrusage failed");
      if(trial)out<<",\n";
      out<<" {\"trial\": "<<trial<<", \"keygen_total_ms\": "<<ms(begin,keyend)<<", \"keygen_per_user_ms\": "<<ms(begin,keyend)/users<<", \"registration_total_ms\": "<<ms(regstart,regend)<<", \"registration_per_user_ms\": "<<ms(regstart,regend)/users<<", \"registration_ms\": [";
      for(std::size_t i=0; i<registrations.size(); ++i) {
        if(i)out<<", ";
        out<<registrations[i];
      }
      out<<"], \"witness_ms\": "<<ms(regend,wend)<<", \"witness_serialization_ms\": "<<ms(wend,wsend)<<", \"encrypt_ms\": "<<ms(encstart,encend)<<", \"ciphertext_serialization_ms\": "<<ms(encend,serend)<<", \"encrypt_and_serialize_ms\": "<<ms(encstart,serend)<<", \"ciphertext_parse_ms\": "<<ms(serend,parseend)<<", \"decrypt_ms\": "<<ms(parseend,decend)<<", \"parse_and_decrypt_ms\": "<<ms(serend,decend)<<", \"ciphertext_bytes\": "<<bytes.size()<<", \"witness_bytes\": "<<wb.size()<<", \"state_bytes\": "<<st.size()<<", \"log_bytes\": "<<log.size()<<", \"secret_key_bytes\": "<<encode_sk(keys[0].secret_key,p).size()<<", \"live_internal_nodes\": "<<reg.live_nodes()<<", \"rebuilt_internal_nodes\": "<<reg.rebuilt_nodes<<", \"gaussian_samples\": "<<stats.gaussian_samples<<", \"large_candidates\": "<<stats.large_candidates<<", \"large_rejections\": "<<stats.large_rejections<<", \"gaussian_refinements\": "<<stats.refinements<<", \"quantized_coefficients\": "<<stats.quantized_coefficients<<", \"encryption_random_bytes_consumed\": "<<stats.random_bytes<<", \"peak_rss_kib\": "<<usage.ru_maxrss<<", \"roundtrip\": true}";
    }
    out<<"\n ]\n}\n";
    if(!a.get("out").empty())save_text(a.get("out"),out.str());
    else std::cout<<out.str();
  }
  const char* help=R"(Shorter RBE research artifact (C++20). All options take values.
  params [--preset main] [--out params.json]
  setup --dir DIR [--preset main] [--test-seed TEST_ONLY]
  keygen --dir DIR --out PREFIX [--test-seed TEST_ONLY]
  identity [--preset main] --label TEXT
  register --dir DIR --id TRITS --public-key FILE
  witness --dir DIR --id TRITS --out FILE [--version V]
  encrypt --dir DIR --id TRITS --message FILE --out FILE [--state FILE] [--test-seed TEST_ONLY]
  decrypt --dir DIR --secret-key FILE --witness FILE --ciphertext FILE --out FILE
  demo --out NEW_DIRECTORY [--preset main] [--test-seed TEST_ONLY]
  benchmark [--preset main] [--users 4] [--iterations 3] [--out results.json]
  quantizer-vectors [--qmax 64]
  gaussian-vectors
Presets: main, matched, two-independent, two-radix, published-gadget, toy.
Messages are exactly phi bits (32 bytes for main). No CCA security or authentication.
Default randomness: OpenSSL CSPRNG. TEST-ONLY seeds disclose all generated secrets.
)";
}
int main(int argc,char** argv) {
  try {
    Args a(argc,argv);
    if(a.command=="help") {
      a.allow( {
      });
      std::cout<<help;
      return 0;
    }
    if(a.command=="params") {
      a.allow( {
        "preset","out"
      });
      auto s=Params::get(a.get("preset","main")).json();
      if(a.get("out").empty())std::cout<<s;
      else save_text(a.get("out"),s);
      return 0;
    }
    if(a.command=="identity") {
      a.allow( {
        "preset","label"
      });
      std::cout<<identity_label(Params::get(a.get("preset","main")),a.need("label"))<<'\n';
      return 0;
    }
    if(a.command=="demo") {
      demo(a);
      return 0;
    }
    if(a.command=="benchmark") {
      benchmark(a);
      return 0;
    }
    if(a.command=="quantizer-vectors") {
      a.allow( {
        "qmax"
      });
      u64 maximum=integer(a.get("qmax","64"));
      require(maximum>=2&&maximum<=128,"qmax range");
      std::cout<<"q,M,a,denominator,k0,w0,k1,w1,k2,w2\n";
      for(u64 q=2; q<=maximum; ++q)for(u64 M=2; M<=q; ++M)for(u64 x=0; x<q; ++x) {
        auto w=quantizer_weights(x,q,M);
        std::cout<<q<<','<<M<<','<<x<<','<<decimal(w.denominator);
        for(unsigned j=0; j<3; ++j)std::cout<<','<<w.k[j]<<','<<decimal(w.w[j]);
        std::cout<<'\n';
      }
      return 0;
    }
    if(a.command=="gaussian-vectors") {
      a.allow( {
      });
      std::cout<<"k,j,t,P,lower,upper\n";
      for(u64 t: {
        1ULL,12500000000ULL,46875000000ULL,187500000000ULL
      })for(u64 k: {
        0ULL,1ULL,32ULL,383ULL,384ULL
      })for(u64 j:std::array<u64,3> {
        0,t/2,t-1
      })for(unsigned P: {
        64U,384U
      }) {
        auto v=acceptance_interval(k,j,t,P);
        std::cout<<k<<','<<j<<','<<t<<','<<P<<','<<v.lo<<','<<v.hi<<'\n';
      }
      return 0;
    }
    if(a.command=="setup") {
      a.allow( {
        "dir","preset","test-seed"
      });
      auto dir=std::filesystem::path(a.need("dir"));
      require_new(dir);
      auto p=Params::get(a.get("preset","main"));
      Random rng(a.seed());
      auto pp=Engine::setup(p,rng);
      Engine e(pp);
      Registry reg(e);
      write_file(dir/"parameters.bin",encode_pp(pp));
      save_text(dir/"preset.txt",p.name+"\n");
      save_text(dir/"params.json",p.json());
      write_file(dir/"registry.log", {
      });
      write_file(dir/"state.bin",encode_state(reg.state(),p));
      std::cout<<"{\"setup\": true, \"public_parameter_bytes\": "<<p.pp_bytes()<<"}\n";
      return 0;
    }
    if(a.command=="keygen") {
      a.allow( {
        "dir","out","test-seed"
      });
      auto e=load_engine(a.need("dir"));
      Random rng(a.seed());
      auto prefix=a.need("out");
      require(!std::filesystem::exists(prefix+".pk")&&!std::filesystem::exists(prefix+".sk"),"refusing to replace key pair");
      auto k=e.keygen(rng);
      write_file(prefix+".pk",encode_pk(k.public_key,e.p()));
      write_file(prefix+".sk",encode_sk(k.secret_key,e.p()),true);
      std::cout<<"{\"keygen\": true}\n";
      return 0;
    }
    if(a.command=="register") {
      a.allow( {
        "dir","id","public-key"
      });
      std::filesystem::path dir=a.need("dir");
      Lock lock(dir/"registry.lock");
      auto e=load_engine(dir);
      Registry reg(e);
      load_registry(dir,reg,e.p());
      auto st=reg.register_key(a.need("id"),decode_pk(read_file(a.need("public-key")),e.p()));
      write_file(dir/"registry.log",encode_log(reg,e.p()));
      write_file(dir/"state.bin",encode_state(st,e.p()));
      std::cout<<"{\"version\": "<<reg.version()<<"}\n";
      return 0;
    }
    if(a.command=="witness") {
      a.allow( {
        "dir","id","out","version"
      });
      auto dir=a.need("dir");
      auto e=load_engine(dir);
      Registry reg(e);
      load_registry(dir,reg,e.p());
      auto v=a.get("version").empty()?reg.version():integer(a.get("version"));
      auto w=reg.witness(a.need("id"),v);
      write_file(a.need("out"),encode_witness(w,e.p()));
      std::cout<<"{\"snapshot\": "<<v<<", \"created\": "<<w.created<<", \"slot\": "<<w.slot<<"}\n";
      return 0;
    }
    if(a.command=="encrypt") {
      a.allow( {
        "dir","id","message","out","state","test-seed"
      });
      std::filesystem::path dir=a.need("dir");
      auto e=load_engine(dir);
      auto st=decode_state(read_file(a.get("state",(dir/"state.bin").string())),e.p());
      Random rng(a.seed());
      auto ct=e.encrypt(st,a.need("id"),decode_message(read_file(a.need("message")),e.p()),rng);
      auto bytes=encode_ct(ct,e.p());
      write_file(a.need("out"),bytes);
      std::cout<<"{\"ciphertext_bytes\": "<<bytes.size()<<"}\n";
      return 0;
    }
    if(a.command=="decrypt") {
      a.allow( {
        "dir","secret-key","witness","ciphertext","out"
      });
      auto e=load_engine(a.need("dir"));
      auto m=e.decrypt(decode_sk(read_file(a.need("secret-key")),e.p()),decode_witness(read_file(a.need("witness")),e.p()),decode_ct(read_file(a.need("ciphertext")),e.p()));
      write_file(a.need("out"),encode_message(m,e.p()),true);
      std::cout<<"{\"decrypted\": true}\n";
      return 0;
    }
    throw Error("unknown command; use rbe_cli help");
  }
  catch(const std::exception& e) {
    std::cerr<<"error: "<<e.what()<<'\n';
    return 1;
  }
}
