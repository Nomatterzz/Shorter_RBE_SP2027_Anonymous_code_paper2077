#pragma once
// Research implementation: variable-time, CPA security, no authentication.
#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>
#include <optional>
#include <memory>
#include <filesystem>
#include <unordered_set>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/evp.h>
namespace rbe {
using u64=std::uint64_t; using i64=std::int64_t;
using u128=__uint128_t; using i128=__int128_t;
using Bytes=std::vector<std::uint8_t>;
using Poly=std::vector<u64>; using SPoly=std::vector<i64>;
using Vec=std::vector<Poly>; using SVec=std::vector<SPoly>; using Matrix=std::vector<Vec>;
using Identity=std::string; using Message=std::vector<std::uint8_t>;
using BigInt=boost::multiprecision::cpp_int;
struct Error:std::runtime_error {using std::runtime_error::runtime_error;};
inline void require(bool b,std::string_view s){if(!b)throw Error(std::string(s));}
inline u64 reduce_signed(i128 a,u64 q){i128 v=a%static_cast<i128>(q);return static_cast<u64>(v<0?v+q:v);}
inline i64 centered(u64 a,u64 q){return a>q/2?static_cast<i64>(a)-static_cast<i64>(q):static_cast<i64>(a);}
inline unsigned bits_for(u64 a){unsigned b=0;do{++b;a>>=1;}while(a);return b;}
inline i64 round_div(i128 a,u64 g){a+=g/2;i128 v=a/static_cast<i128>(g);if(a<0&&a%g)--v;return static_cast<i64>(v);}
std::string decimal(u128); std::string sha256(const Bytes&);
struct U256 {
 std::array<u64,4> limb{};
 bool operator<(const U256& b) const {for(int i=3;i>=0;--i){auto j=static_cast<std::size_t>(i);if(limb[j]!=b.limb[j])return limb[j]<b.limb[j];}return false;}
 bool operator==(const U256&) const=default;
};
class Random {
 std::array<std::uint8_t,65536> buffer_{};std::size_t pos_=65536;EVP_CIPHER_CTX* test_=nullptr;
 void refill();
public:
 u64 consumed=0,generated=0,rejections=0;
 explicit Random(std::optional<std::string> test_seed=std::nullopt);~Random();
 Random(const Random&)=delete;Random& operator=(const Random&)=delete;
 void fill(std::uint8_t*,std::size_t);u64 word();bool bit();U256 word256();u64 below(u64);u128 below128(u128);
};
enum class Decomposition{One,Independent,Radix};
struct Params {
 std::string name="main";
 std::size_t phi=256,n=7,L=162;
 u64 q=281474976694273ULL,capacity=1ULL<<30,K=1ULL<<15,U=1ULL<<19,V=1ULL<<27;
 u64 sigma=32,sigma_tilde=6000000000000ULL,radix=0;unsigned kappa=34,digits=0,dropped=0;
 Decomposition decomposition=Decomposition::One;std::vector<u64> scales{1ULL<<28};
 std::size_t slots()const{return bits_for(capacity);}std::size_t d()const{return scales.size();}
 std::size_t width()const{return 3*n*d();}std::size_t header_polys()const{return L*width()+n;}
 std::size_t ciphertext_polys()const{return header_polys()+slots();}u64 M()const{return 1ULL<<kappa;}
 unsigned counter_bytes()const{return (bits_for(capacity)+7)/8;}unsigned q_bytes()const{return (bits_for(q-1)+7)/8;}
 unsigned identity_bytes()const;unsigned secret_bits()const{return bits_for(2*K);}unsigned witness_bits()const{return bits_for(2*U);}
 std::size_t ciphertext_bytes()const{return counter_bytes()+(ciphertext_polys()*phi*kappa+7)/8;}
 std::size_t witness_bytes()const{return counter_bytes()+1+(L*width()*phi*witness_bits()+7)/8;}
 std::size_t pp_bytes()const{return (n*width()+n*n+n*slots())*phi*q_bytes();}
 void validate()const;void check_identity(const Identity&)const;void check_key(const Vec&)const;
 std::string json()const;static Params get(const std::string&);static std::vector<std::string> names();
};
struct Decomposed{std::vector<i64> u;i64 residual;};
Decomposed decompose(u64,const Params&);SVec decompose_label(const Vec&,const Params&);
u64 mul_mod(u64,u64,u64);u64 pow_mod(u64,u64,u64);bool prime64(u64);
class NTT {
 std::size_t size_;u64 q_,psi_;Poly twist_,untwist_;std::vector<std::size_t> reversal_;std::vector<Poly> roots_,iroots_;
 void cyclic(Poly&,bool)const;
public:
 NTT(std::size_t,u64);std::size_t size()const{return size_;}u64 modulus()const{return q_;}u64 psi()const{return psi_;}
 Poly forward(const Poly&)const;Poly forward(const SPoly&)const;Poly inverse(Poly)const;Poly product(const Poly&,const Poly&)const;
};
Poly schoolbook(const Poly&,const Poly&,u64);
class CRTDot {
 std::array<NTT,3> ntt_;u64 inv12_,inv123_;u128 product_;
public:
 explicit CRTDot(std::size_t);Poly compute(const Vec&,const SVec&,u64)const;
};
struct Interval{BigInt lo,hi;};
Interval exp_negative_interval(const BigInt&,const BigInt&,unsigned);
Interval acceptance_interval(u64,u64,u64,unsigned);U256 as_u256(const BigInt&);
bool gaussian_bernoulli(u64,u64,u64,const U256&,bool* refined=nullptr);
class Gaussian {
 Random& rng_;
public:
 u64 small_samples=0,large_samples=0,candidates=0,rejections=0,refinements=0;
 explicit Gaussian(Random& r):rng_(r){};i64 small(u64);i64 large(u64);
};
struct Weights{std::array<i64,3> k{};std::array<u128,3> w{};std::size_t count=0;u128 denominator=0;};
Weights quantizer_weights(u64,u64,u64);u64 quantize(u64,u64,u64,Random&);
struct PublicParameters{Params p;Matrix A1c,B;std::vector<Vec> terminators;};
struct KeyPair{Vec public_key;SVec secret_key;};
struct State{u64 version=0;std::vector<Vec> roots;};
struct Witness{u64 created=0;std::size_t slot=0;SVec openings;bool operator==(const Witness&)const=default;};
struct Ciphertext{u64 version=0;Vec components;};
struct EncryptStats{u64 gaussian_samples=0,large_candidates=0,large_rejections=0,refinements=0,quantized_coefficients=0,random_bytes=0;};
class Engine {
 PublicParameters pp_;NTT ntt_;CRTDot crt_;Matrix ahat_,bhat_;
 Vec matrix_times(const Matrix&,const SVec&)const;Vec transpose_times(const Matrix&,const Vec&)const;
public:
 explicit Engine(PublicParameters);const Params& p()const{return pp_.p;}const PublicParameters& pp()const{return pp_;}
 static PublicParameters setup(const Params&,Random&);KeyPair keygen(Random&)const;Vec node_hash(const SVec&)const;
 Ciphertext encrypt(const State&,const Identity&,const Message&,Random&,EncryptStats* stats=nullptr)const;
 Message decrypt(const SVec&,const Witness&,const Ciphertext&)const;
};
struct Record{Identity id;Vec key;};using RecordPtr=std::shared_ptr<const Record>;
struct Node{enum class Kind{Leaf,Internal};Kind kind=Kind::Leaf;Vec label;SVec opening;std::array<std::shared_ptr<const Node>,3> children{};};
struct Bucket{u64 created=0;std::vector<RecordPtr> records;std::unordered_set<Identity> identities;std::shared_ptr<const Node> root;};using BucketPtr=std::shared_ptr<const Bucket>;
class Registry {
 const Engine& engine_;bool retain_;std::vector<BucketPtr> slots_;std::vector<std::vector<BucketPtr>> snapshots_;
 std::vector<RecordPtr> log_;std::unordered_set<Identity> ids_;
 std::shared_ptr<const Node> build(const std::vector<RecordPtr>&,std::size_t,std::size_t);
 std::vector<BucketPtr> view(u64)const;State make_state(const std::vector<BucketPtr>&,u64)const;
public:
 u64 rebuilt_nodes=0;explicit Registry(const Engine&,bool retain_snapshots=false);Registry(Engine&&)=delete;
 u64 version()const{return log_.size();}const std::vector<RecordPtr>& log()const{return log_;}
 State state()const;State state_at(u64)const;State register_key(const Identity&,const Vec&);
 Witness witness(const Identity&,u64)const;Witness witness(const Identity& id)const{return witness(id,version());}
 void verify_invariants(bool nodes=true)const;std::size_t live_nodes()const;
};
Identity identity_counter(const Params&,u64);Identity identity_label(const Params&,const std::string&);
Bytes pack_values(const std::vector<u64>&,unsigned);std::vector<u64> unpack_values(const Bytes&,std::size_t,unsigned);
Bytes encode_pp(const PublicParameters&);PublicParameters decode_pp(const Bytes&,const Params&);
Bytes encode_pk(const Vec&,const Params&);Vec decode_pk(const Bytes&,const Params&);
Bytes encode_sk(const SVec&,const Params&);SVec decode_sk(const Bytes&,const Params&);
Bytes encode_state(const State&,const Params&);State decode_state(const Bytes&,const Params&);
Bytes encode_witness(const Witness&,const Params&);Witness decode_witness(const Bytes&,const Params&);
Bytes encode_ct(const Ciphertext&,const Params&);Ciphertext decode_ct(const Bytes&,const Params&);
Bytes encode_message(const Message&,const Params&);Message decode_message(const Bytes&,const Params&);
Bytes encode_log(const Registry&,const Params&);void replay_log(const Bytes&,Registry&,const Params&);
Bytes read_file(const std::filesystem::path&,std::size_t max_bytes=1ULL<<30);
void write_file(const std::filesystem::path&,const Bytes&,bool secret=false);
} // namespace rbe
