#include "rbe/rbe.hpp"
#include <algorithm>
#include <functional>
namespace rbe {
  namespace {
    Matrix transformed(const Matrix& a,const NTT& nt) {
      Matrix x;
      for(const auto& row:a) {
        Vec r;
        for(const auto& p:row)r.push_back(nt.forward(p));
        x.push_back(std::move(r));
      }
      return x;
    }
    void signed_shape(const SVec& a,std::size_t rows,const Params& p,u64 bound) {
      require(a.size()==rows,"signed vector rank mismatch");
      for(const auto& x:a) {
        require(x.size()==p.phi,"signed vector degree mismatch");
        for(auto v:x)require(v>=-static_cast<i64>(bound)&&v<=static_cast<i64>(bound),"signed coefficient out of range");
      }
    }
  }
  PublicParameters Engine::setup(const Params& p,Random& rng) {
    p.validate();
    require(prime64(p.q),"source modulus must be prime");
    PublicParameters pp;
    pp.p=p;
    pp.A1c=Matrix(p.n,Vec(p.width(),Poly(p.phi)));
    pp.B=Matrix(p.n,Vec(p.n,Poly(p.phi)));
    pp.terminators=std::vector<Vec>(p.slots(),Vec(p.n,Poly(p.phi)));
    for(auto* m: {
      &pp.A1c,&pp.B
    })for(auto& row:*m)for(auto& a:row)for(auto& x:a)x=rng.below(p.q);
    for(auto& t:pp.terminators)for(auto& a:t)for(auto& x:a)x=rng.below(p.q);
    return pp;
  }
  Engine::Engine(PublicParameters pp):pp_(std::move(pp)),ntt_(pp_.p.phi,pp_.p.q),crt_(pp_.p.phi) {
    p().validate();
    require(pp_.A1c.size()==p().n&&pp_.B.size()==p().n&&pp_.terminators.size()==p().slots(),"public parameter shape");
    for(const auto& row:pp_.A1c) {
      require(row.size()==p().width(),"A width");
      for(const auto& a:row) {
        require(a.size()==p().phi,"A degree");
        for(auto x:a)require(x<p().q,"noncanonical A");
      }
    }
    for(const auto& row:pp_.B)p().check_key(row);
    for(const auto& t:pp_.terminators)p().check_key(t);
    ahat_=transformed(pp_.A1c,ntt_);
    bhat_=transformed(pp_.B,ntt_);
  }
  Vec Engine::matrix_times(const Matrix& a,const SVec& u)const {
    require(a.size()==p().n&&u.size()==a[0].size(),"matrix/vector mismatch");
    Vec hat;
    for(const auto& z:u)hat.push_back(ntt_.forward(z));
    Vec result(p().n,Poly(p().phi));
    for(std::size_t i=0; i<p().n; ++i) {
      std::vector<u128> acc(p().phi);
      for(std::size_t j=0; j<u.size(); ++j)for(std::size_t k=0; k<p().phi; ++k)acc[k]+=static_cast<u128>(a[i][j][k])*hat[j][k];
      for(std::size_t k=0; k<p().phi; ++k)result[i][k]=static_cast<u64>(acc[k]%p().q);
      result[i]=ntt_.inverse(std::move(result[i]));
    }
    return result;
  }
  Vec Engine::transpose_times(const Matrix& a,const Vec& rhat)const {
    Vec result(a[0].size(),Poly(p().phi));
    for(std::size_t j=0; j<result.size(); ++j) {
      std::vector<u128> acc(p().phi);
      for(std::size_t i=0; i<p().n; ++i)for(std::size_t k=0; k<p().phi; ++k)acc[k]+=static_cast<u128>(a[i][j][k])*rhat[i][k];
      for(std::size_t k=0; k<p().phi; ++k)result[j][k]=static_cast<u64>(acc[k]%p().q);
      result[j]=ntt_.inverse(std::move(result[j]));
    }
    return result;
  }
  KeyPair Engine::keygen(Random& rng)const {
    KeyPair k;
    k.secret_key=SVec(p().n,SPoly(p().phi));
    SVec z=k.secret_key;
    for(auto* v: {
      &k.secret_key,&z
    })for(auto& a:*v)for(auto& x:a)x=static_cast<i64>(rng.below(2*p().K+1))-static_cast<i64>(p().K);
    k.public_key=matrix_times(bhat_,k.secret_key);
    for(std::size_t i=0; i<p().n; ++i)for(std::size_t j=0; j<p().phi; ++j)k.public_key[i][j]=reduce_signed(static_cast<i128>(k.public_key[i][j])+z[i][j],p().q);
    return k;
  }
  Vec Engine::node_hash(const SVec& u)const {
    signed_shape(u,p().width(),p(),p().U);
    return matrix_times(ahat_,u);
  }
  Ciphertext Engine::encrypt(const State& st,const Identity& id,const Message& mu,Random& rng,EncryptStats* stats)const {
    const auto& pp=p();
    pp.check_identity(id);
    require(st.version<=pp.capacity&&st.roots.size()==pp.slots(),"state shape");
    for(const auto& y:st.roots)pp.check_key(y);
    require(mu.size()==pp.phi&&std::all_of(mu.begin(),mu.end(),[](auto x) {
      return x<=1;
    }),"message must contain phi bits");
    u64 start=rng.consumed;
    Gaussian gs(rng);
    std::vector<SVec> r(pp.L+1,SVec(pp.n,SPoly(pp.phi)));
    std::vector<Vec> rh(pp.L+1);
    for(std::size_t j=0; j<=pp.L; ++j)for(auto& a:r[j]) {
      for(auto& x:a)x=gs.small(pp.sigma);
      rh[j].push_back(ntt_.forward(a));
    }
    Ciphertext ct;
    ct.version=st.version;
    ct.components.reserve(pp.ciphertext_polys());
    for(std::size_t j=0; j<pp.L; ++j) {
      auto c=transpose_times(ahat_,rh[j]);
      std::size_t child=static_cast<std::size_t>(id[j]-'0');
      for(std::size_t k=0; k<pp.width(); ++k)for(std::size_t h=0; h<pp.phi; ++h) {
        i128 x=static_cast<i128>(c[k][h])+gs.small(pp.sigma);
        if(k/(pp.n*pp.d())==child) {
          std::size_t v=k%(pp.n*pp.d());
          x+=static_cast<i128>(pp.scales[v%pp.d()])*r[j+1][v/pp.d()][h];
        }
        c[k][h]=reduce_signed(x,pp.q);
      }
      for(auto& a:c)ct.components.push_back(std::move(a));
    }
    auto terminal=transpose_times(bhat_,rh[pp.L]);
    for(auto& a:terminal) {
      for(auto& x:a)x=reduce_signed(static_cast<i128>(x)+gs.small(pp.sigma),pp.q);
      ct.components.push_back(std::move(a));
    }
    for(std::size_t t=0; t<pp.slots(); ++t) {
      std::vector<u128> acc(pp.phi);
      for(std::size_t i=0; i<pp.n; ++i) {
        auto yh=ntt_.forward(st.roots[t][i]);
        for(std::size_t h=0; h<pp.phi; ++h)acc[h]+=static_cast<u128>(rh[0][i][h])*yh[h];
      }
      Poly d(pp.phi);
      for(std::size_t h=0; h<pp.phi; ++h)d[h]=static_cast<u64>(acc[h]%pp.q);
      d=ntt_.inverse(std::move(d));
      for(std::size_t h=0; h<pp.phi; ++h)d[h]=reduce_signed(static_cast<i128>(d[h])+gs.large(pp.sigma_tilde)+static_cast<i128>(pp.q/2)*mu[h],pp.q);
      ct.components.push_back(std::move(d));
    }
    for(auto& a:ct.components)for(auto& x:a)x=quantize(x,pp.q,pp.M(),rng);
    if(stats)*stats= {
      gs.small_samples+gs.large_samples,gs.candidates,gs.rejections,gs.refinements,static_cast<u64>(pp.ciphertext_polys()*pp.phi),rng.consumed-start
    };
    return ct;
  }
  Message Engine::decrypt(const SVec& x,const Witness& w,const Ciphertext& ct)const {
    const auto& pp=p();
    signed_shape(x,pp.n,pp,pp.K);
    signed_shape(w.openings,pp.L*pp.width(),pp,pp.U);
    require(w.created>0&&w.created<=ct.version&&ct.version<=pp.capacity&&w.slot<pp.slots(),"witness/snapshot mismatch");
    require(ct.components.size()==pp.ciphertext_polys(),"ciphertext shape");
    for(const auto& a:ct.components) {
      require(a.size()==pp.phi,"ciphertext degree");
      for(auto z:a)require(z<pp.M(),"noncanonical ciphertext");
    }
    Vec header(ct.components.begin(),ct.components.begin()+static_cast<std::ptrdiff_t>(pp.header_polys()));
    SVec opening=w.openings;
    opening.insert(opening.end(),x.begin(),x.end());
    Poly dot=crt_.compute(header,opening,pp.M());
    const Poly& d=ct.components[pp.header_polys()+w.slot];
    Message out(pp.phi);
    for(std::size_t i=0; i<pp.phi; ++i) {
      u64 a=(d[i]+pp.M()-dot[i])%pp.M();
      out[i]=static_cast<std::uint8_t>(((a+pp.M()/4)/(pp.M()/2))&1);
    }
    return out;
  }
  Registry::Registry(const Engine& e,bool retain):engine_(e),retain_(retain),slots_(e.p().slots()) {
    if(retain_)snapshots_.push_back(slots_);
  }
  std::shared_ptr<const Node> Registry::build(const std::vector<RecordPtr>& records,std::size_t depth,std::size_t slot) {
    if(records.empty())return {
    };
    auto node=std::make_shared<Node>();
    const auto& p=engine_.p();
    if(depth==p.L) {
      require(records.size()==1,"duplicate leaf");
      node->label=records[0]->key;
      node->kind=Node::Kind::Leaf;
      return node;
    }
    node->kind=Node::Kind::Internal;
    std::array<std::vector<RecordPtr>,3> partitions;
    for(const auto& r:records)partitions[static_cast<std::size_t>(r->id[depth]-'0')].push_back(r);
    for(std::size_t i=0; i<3; ++i) {
      node->children[i]=build(partitions[i],depth+1,slot);
      auto u=decompose_label(node->children[i]?node->children[i]->label:engine_.pp().terminators[slot],p);
      node->opening.insert(node->opening.end(),u.begin(),u.end());
    }
    node->label=engine_.node_hash(node->opening);
    ++rebuilt_nodes;
    return node;
  }
  State Registry::make_state(const std::vector<BucketPtr>& slots,u64 v)const {
    State st;
    st.version=v;
    for(std::size_t i=0; i<slots.size(); ++i)st.roots.push_back(slots[i]?slots[i]->root->label:engine_.pp().terminators[i]);
    return st;
  }
  State Registry::state()const {
    return make_state(slots_,version());
  }
  std::vector<BucketPtr> Registry::view(u64 v)const {
    require(v<=version(),"unknown historical snapshot");
    if(v==version())return slots_;
    if(retain_)return snapshots_.at(static_cast<std::size_t>(v));
    Registry replay(engine_,false);
    for(std::size_t i=0; i<v; ++i)replay.register_key(log_[i]->id,log_[i]->key);
    return replay.slots_;
  }
  State Registry::state_at(u64 v)const {
    return make_state(view(v),v);
  }
  State Registry::register_key(const Identity& id,const Vec& key) {
    const auto& p=engine_.p();
    p.check_identity(id);
    p.check_key(key);
    require(version()<p.capacity,"registration capacity exhausted");
    require(!ids_.contains(id),"identity already registered");
    auto record=std::make_shared<Record>(Record {
      id,key
    });
    std::vector<RecordPtr> records {
      record
    };
    std::size_t slot=0;
    while(slot<slots_.size()&&slots_[slot]) {
      records.insert(records.end(),slots_[slot]->records.begin(),slots_[slot]->records.end());
      ++slot;
    }
    require(slot<slots_.size(),"capacity bookkeeping failure");
    auto bucket=std::make_shared<Bucket>();
    bucket->created=version()+1;
    bucket->records=std::move(records);
    for(const auto& entry:bucket->records) bucket->identities.insert(entry->id);
    bucket->root=build(bucket->records,0,slot);
    // Validation and tree construction finish before replacing public roots.
    log_.push_back(record);
    ids_.insert(id);
    for(std::size_t i=0; i<slot; ++i)slots_[i].reset();
    slots_[slot]=std::move(bucket);
    if(retain_)snapshots_.push_back(slots_);
    return state();
  }
  Witness Registry::witness(const Identity& id,u64 v)const {
    engine_.p().check_identity(id);
    auto slots=view(v);
    for(std::size_t t=0; t<slots.size(); ++t)if(slots[t]) {
      const auto& b=slots[t];
      bool present=b->identities.contains(id);
      if(!present)continue;
      Witness w;
      w.created=b->created;
      w.slot=t;
      auto node=b->root;
      for(std::size_t j=0; j<id.size(); ++j) {
        require(node&&node->kind==Node::Kind::Internal,"invalid membership path");
        w.openings.insert(w.openings.end(),node->opening.begin(),node->opening.end());
        node=node->children[static_cast<std::size_t>(id[j]-'0')];
      }
      require(node&&node->kind==Node::Kind::Leaf,"membership path ended incorrectly");
      return w;
    }
    throw Error("identity absent at requested snapshot");
  }
  void Registry::verify_invariants(bool nodes)const {
    std::unordered_set<Identity> seen;
    std::size_t count=0;
    for(std::size_t t=0; t<slots_.size(); ++t) {
      bool occupied=((version()>>t)&1)!=0;
      require(static_cast<bool>(slots_[t])==occupied,"binary-counter occupancy invariant");
      if(!occupied)continue;
      const auto& b=slots_[t];
      require(b->created>0&&b->created<=version()&&b->records.size()==(std::size_t {
        1
      }
      <<t),"bucket size invariant");
      for(const auto& r:b->records) {
        require(seen.insert(r->id).second,"duplicate identity across buckets");
        ++count;
      }
      if(nodes) {
        std::function<void(const std::shared_ptr<const Node>&,std::size_t)> visit=[&](const auto& node,std::size_t depth) {
          if(!node)return;
          if(depth==engine_.p().L) {
            require(node->kind==Node::Kind::Leaf,"incorrect leaf type");
            return;
          }
          require(node->kind==Node::Kind::Internal,"incorrect internal type");
          SVec opening;
          for(const auto& child:node->children) {
            auto u=decompose_label(child?child->label:engine_.pp().terminators[t],engine_.p());
            opening.insert(opening.end(),u.begin(),u.end());
            visit(child,depth+1);
          }
          require(opening==node->opening&&engine_.node_hash(opening)==node->label,"node relation invariant");
        };
        visit(b->root,0);
      }
    }
    require(count==version()&&seen.size()==ids_.size(),"registry cardinality invariant");
  }
  std::size_t Registry::live_nodes()const {
    std::size_t count=0;
    std::function<void(const std::shared_ptr<const Node>&)> visit=[&](const auto& n) {
      if(!n)return;
      if(n->kind==Node::Kind::Internal)++count;
      for(const auto& c:n->children)visit(c);
    };
    for(const auto& b:slots_)if(b)visit(b->root);
    return count;
  }
  Identity identity_counter(const Params& p,u64 x) {
    Identity id(p.L,'0');
    for(std::size_t j=p.L; j>0; --j) {
      id[j-1]=static_cast<char>('0'+x%3);
      x/=3;
    }
    require(x==0,"identity counter exceeds space");
    return id;
  }
  Identity identity_label(const Params& p,const std::string& label) {
    require(p.L>=162,"hashed identities require at least 162 trits");
    std::string s="RBE-APPLICATION-IDENTITY-v1:"+label;
    std::string h=sha256(Bytes(s.begin(),s.end()));
    BigInt x("0x"+h);
    Identity id(p.L,'0');
    for(std::size_t j=p.L; j>0; --j) {
      id[j-1]=static_cast<char>('0'+(x%3).convert_to<unsigned>());
      x/=3;
    }
    require(x==0,"identity hash overflow");
    return id;
  }
}
// namespace rbe
