#include "bc3hash-core.hpp"
#include "bc3hash-constants.hpp"
#include "bc3hash-uint.hpp"
#include "bc3hash-hashes.hpp"
#include <secp256k1.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace bc3 {
namespace detail {
using namespace constants;
namespace {
// Set at runtime by -a bc3hash:W. Frozen once the tables exist, since they are
// sized for the window they were built at.
unsigned curve_window = BC3_CURVE_WINDOW;
bool tables_frozen = false;

unsigned active_window()
{
    return curve_window;
}
const FixedExponent<M64, 3> exp64(E64);
const FixedExponent<M128, 4> exp128(E128);
const FixedExponent<M256, 4> exp256(E256);
struct SecpContext {
    secp256k1_context* p = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    SecpContext()
    {
        if (!p) throw std::bad_alloc();
    }
    ~SecpContext() { secp256k1_context_destroy(p); }
};
const SecpContext& context()
{
    // Never destroyed: the miner calls exit() with hashing threads still running.
    static const SecpContext& c = *new SecpContext;
    return c;
}
struct alignas(64) CurveTable {
    const unsigned window = active_window();
    const unsigned digits = (256 + window - 1) / window;
    const unsigned entries = (1u << window) - 1;
    const unsigned last_entries = (1u << (256 - window * (digits - 1))) - 1;
    // Each opaque public key occupies one cache line. The final window has
    // fewer bits; omit unreachable entries instead of padding that row.
    // C++17 aligned new lets std::vector honour the alignas.
    struct alignas(64) Key {
        secp256k1_pubkey value;
    };
    // Frozen in the ctor rather than fetched per call: operator() runs 64x per
    // hash and context() is a function-local static, so calling it there is a
    // guard load on every one of those.
    secp256k1_context* ctx = nullptr;
    static_assert(sizeof(secp256k1_pubkey) == 64, "one cache line per table entry");
    std::vector<Key> table;
    CurveTable(U256 x, U256 y) : table((digits - 1) * entries + last_entries)
    {
        ctx = context().p;
        std::array<unsigned char, 65> encoded{};
        encoded[0] = 4;
        x.store(encoded.data() + 1);
        y.store(encoded.data() + 33);
        secp256k1_pubkey base;
        if (!secp256k1_ec_pubkey_parse(ctx, &base, encoded.data(), 65)) throw std::runtime_error("Invalid BC3 curve constant");
        for (unsigned i = 0; i < digits; ++i) {
            auto* row = table.data() + i * entries;
            const unsigned count = i + 1 == digits ? last_entries : entries;
            row[0].value = base;
            for (unsigned j = 1; j < count; ++j) {
                const secp256k1_pubkey* points[] = {&row[j - 1].value, &base};
                if (!secp256k1_ec_pubkey_combine(ctx, &row[j].value, points, 2)) throw std::runtime_error("BC3 curve table failure");
            }
            if (i + 1 < digits) {
                const secp256k1_pubkey* points[] = {&row[entries - 1].value, &row[0].value};
                if (!secp256k1_ec_pubkey_combine(ctx, &base, points, 2)) throw std::runtime_error("BC3 curve table failure");
            }
        }
    }
    std::pair<U256, U256> operator()(U256 k) const
    {
        const U256 order = U256::hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        if (k >= order) k = k - order;
        if (k.zero()) return {INVALID_POINT_x, INVALID_POINT_y};
        std::array<const secp256k1_pubkey*, 26> points;
        std::size_t n = 0;
        for (unsigned i = 0; i < digits; ++i) {
            const unsigned pos = i * window, limb = pos / 64, shift = pos % 64;
            std::uint64_t b = k.v[limb] >> shift;
            if (shift && limb + 1 < 4) b |= k.v[limb + 1] << (64 - shift);
            b &= entries;
            if (b) {
                points[n] = &table[i * entries + b - 1].value;
                // Issue independent cache misses together, ahead of the
                // library's dependent sequence of elliptic-curve additions.
                __builtin_prefetch(points[n], 0, 3);
                ++n;
            }
        }
        secp256k1_pubkey result;
        if (!secp256k1_ec_pubkey_combine(ctx, &result, points.data(), n)) throw std::runtime_error("BC3 point combination failed");
        std::array<unsigned char, 65> encoded;
        std::size_t length = encoded.size();
        if (!secp256k1_ec_pubkey_serialize(ctx, encoded.data(), &length, &result, SECP256K1_EC_UNCOMPRESSED)) throw std::runtime_error("BC3 point serialization failed");
        return {U256::load(encoded.data() + 1), U256::load(encoded.data() + 33)};
    }
};
struct Tables {
    FixedPower<F64> pow64{g64};
    FixedPower<F128> pow128{g128};
    FixedPower<F256> pow256{g256};
    std::array<CurveTable, 4> curve{{{H_x, H_y}, {J_x, J_y}, {K_x, K_y}, {L_x, L_y}}};
};
const Tables& tables()
{
    // Never destroyed, same reason as context(): exit() runs static destructors
    // while miner threads still read the tables.
    static const Tables& t = *new Tables;
    return t;
}
// Coefficients stay in [0,p). This is variable-time arithmetic on public
// hash inputs, never a secret-key primitive.
U256 shift_right(U256 x, unsigned n)
{
    if (n == 64) {
        x.v = {x.v[1], x.v[2], x.v[3], 0};
        return x;
    }
    for (unsigned i = 0; i < 3; ++i)
        x.v[i] = (x.v[i] >> n) | (x.v[i + 1] << (64 - n));
    x.v[3] >>= n;
    return x;
}
// Compile-time, not a function-local static: divide_power2_mod sits inside
// inverse256()'s binary-Euclid loop, so a static there is a guard branch per
// iteration. Same six Newton steps, folded at compile time.
constexpr std::uint64_t inverse_odd64(std::uint64_t x)
{
    std::uint64_t y = 1;
    for (unsigned i = 0; i < 6; ++i)
        y *= 2 - x * y;
    return y;
}
constexpr std::uint64_t inv36113 = inverse_odd64(36113);
U256 divide_power2_mod(U256 x, unsigned n)
{
    // Choose q so x + q*p is divisible by 2^n. For p=2^256-C,
    // q = x/C (mod 2^n). x+q*p = (x-q*C) + q*2^256.
    auto q = x.v[0] * inv36113;
    if (n < 64) q &= (std::uint64_t{1} << n) - 1;
    const Wide product = Wide(q) * 36113;
    U256 correction;
    correction.v[0] = std::uint64_t(product);
    correction.v[1] = std::uint64_t(product >> 64);
    const bool borrow = x < correction;
    x = shift_right(x - correction, n);
    x.v[3] |= (q - std::uint64_t(borrow)) << (64 - n);
    return x;
}
U256 subtract_mod(U256 x, U256 y)
{
    return x >= y ? x - y : F256::modulus() - (y - x);
}
U256 scale_mod(U256 x, std::int64_t factor)
{
    const bool negative = factor < 0;
    const auto magnitude = std::uint64_t(negative ? -factor : factor);
    Wide carry = 0;
    for (unsigned i = 0; i < 4; ++i) {
        carry = Wide(x.v[i]) * magnitude + std::uint64_t(carry >> 64);
        x.v[i] = std::uint64_t(carry);
    }
    carry = Wide(std::uint64_t(carry >> 64)) * 36113;
    for (unsigned i = 0; i < 4; ++i) {
        carry += x.v[i];
        x.v[i] = std::uint64_t(carry);
        carry >>= 64;
    }
    if (carry) x = x + U256(36113);
    x = F256::normalize(x);
    return negative && !x.zero() ? F256::modulus() - x : x;
}
U256 add_mod(U256 x, U256 y)
{
    const auto sum = x + y;
    return F256::normalize(sum + (sum < x ? U256(36113) : U256{}));
}
UInt<5> scale_wide(U256 x, std::int64_t factor)
{
    UInt<5> r;
    Wide carry = 0;
    const auto magnitude = std::uint64_t(factor < 0 ? -factor : factor);
    for (unsigned i = 0; i < 4; ++i) {
        carry = Wide(x.v[i]) * magnitude + std::uint64_t(carry >> 64);
        r.v[i] = std::uint64_t(carry);
    }
    r.v[4] = std::uint64_t(carry >> 64);
    return r;
}
U256 linear_positive(U256 u, U256 v, std::int64_t a, std::int64_t b)
{
    const auto au = scale_wide(u, a), bv = scale_wide(v, b);
    return U256(a < 0 ? bv - au : b < 0 ? au - bv :
                                          au + bv);
}
bool euclid_batch(U256& u, U256& v, U256& x, U256& y)
{
    // Infer several exact Euclidean quotients from intervals around the top
    // 62 bits. The omitted low bits lie in [0,1); interval agreement proves
    // the quotient, including when signed matrix coefficients change sides.
    unsigned high = 3;
    while (high && !(u.v[high] | v.v[high]))
        --high;
    if (high == 0) return false;
    const unsigned bits = 64 - unsigned(__builtin_clzll(u.v[high] | v.v[high]));
    const unsigned shift = bits > 62 ? bits - 62 : 0;
    std::uint64_t top_u, top_v;
    if (bits >= 62) {
        top_u = u.v[high] >> shift;
        top_v = v.v[high] >> shift;
    } else {
        top_u = (u.v[high] << (62 - bits)) | (u.v[high - 1] >> (bits + 2));
        top_v = (v.v[high] << (62 - bits)) | (v.v[high - 1] >> (bits + 2));
    }
    std::int64_t a = 1, b = 0, c = 0, d = 1;
    unsigned steps = 0;
    for (; steps < 32; ++steps) {
        const SignedWide nx = SignedWide(a) * top_u + SignedWide(b) * top_v;
        const SignedWide ny = SignedWide(c) * top_u + SignedWide(d) * top_v;
        const auto lx = nx + std::min<std::int64_t>(a, 0) + std::min<std::int64_t>(b, 0);
        const auto hx = nx + std::max<std::int64_t>(a, 0) + std::max<std::int64_t>(b, 0);
        const auto ly = ny + std::min<std::int64_t>(c, 0) + std::min<std::int64_t>(d, 0);
        const auto hy = ny + std::max<std::int64_t>(c, 0) + std::max<std::int64_t>(d, 0);
        if (lx < 0 || ly <= 0) break;
        // The exact remainders decrease from <=2^62; the interval error is
        // <=2^32, so these positive bounds fit in 64 bits.
        const auto q = std::uint64_t(lx) / std::uint64_t(hy);
        if (q != std::uint64_t(hx) / std::uint64_t(ly) || q > INT32_MAX) break;
        const auto next_c = SignedWide(a) - SignedWide(q) * c, next_d = SignedWide(b) - SignedWide(q) * d;
        if (next_c < -INT32_MAX || next_c > INT32_MAX || next_d < -INT32_MAX || next_d > INT32_MAX) break;
        a = c;
        b = d;
        c = std::int64_t(next_c);
        d = std::int64_t(next_d);
    }
    if (steps < 2) return false;
    const auto nu = linear_positive(u, v, a, b), nv = linear_positive(u, v, c, d);
    const auto nx = add_mod(scale_mod(x, a), scale_mod(y, b));
    y = add_mod(scale_mod(x, c), scale_mod(y, d));
    x = nx;
    u = nu;
    v = nv;
    return true;
}
} // namespace
U256 inverse256(U256 a)
{
    a = F256::normalize(a);
    if (a.zero()) return {};
    U256 u = a, v = F256::modulus(), x(1), y;
    const U256 one(1);
    // Binary extended Euclid: u = a*x and v = a*y modulo p.
    while (u != one && v != one) {
        if (!(u.v[1] | u.v[2] | u.v[3] | v.v[1] | v.v[2] | v.v[3]) && ((u.v[0] | v.v[0]) >> 62) == 0) {
            auto small_u = u.v[0], small_v = v.v[0];
            std::int64_t a0 = 1, b0 = 0, a1 = 0, b1 = 1;
            while (small_v) {
                const auto q = small_u / small_v;
                const auto remainder = small_u % small_v;
                const auto next_a = std::int64_t(SignedWide(a0) - SignedWide(q) * a1);
                const auto next_b = std::int64_t(SignedWide(b0) - SignedWide(q) * b1);
                small_u = small_v;
                small_v = remainder;
                a0 = a1;
                b0 = b1;
                a1 = next_a;
                b1 = next_b;
            }
            return add_mod(scale_mod(x, a0), scale_mod(y, b0));
        }
        if (euclid_batch(u, v, x, y)) continue;
        while (!(u.v[0] & 1)) {
            const unsigned n = u.v[0] ? unsigned(__builtin_ctzll(u.v[0])) : 64;
            u = shift_right(u, n);
            x = divide_power2_mod(x, n);
        }
        while (!(v.v[0] & 1)) {
            const unsigned n = v.v[0] ? unsigned(__builtin_ctzll(v.v[0])) : 64;
            v = shift_right(v, n);
            y = divide_power2_mod(y, n);
        }
        if (u == one || v == one) break;
        if (u >= v) {
            u = u - v;
            x = subtract_mod(x, y);
        } else {
            v = v - u;
            y = subtract_mod(y, x);
        }
    }
    return u == one ? x : y;
}
static Digest mix512(const void* input, unsigned folded)
{
    const auto& t = tables();
    const auto* bytes = static_cast<const std::uint8_t*>(input);
    std::array<U64, 32> m64;
    std::array<U128, 48> m128;
    std::array<U256, 64> m256;
    for (unsigned i = 0; i < 8; ++i)
        m64[i] = U64::load(bytes + 8 * i);
    auto c1 = m64[0] ^ base[0], c2 = m64[1] ^ base[1], c3 = m64[2] ^ base[2], c4 = m64[3] ^ base[3];
    auto c5 = m64[4] ^ base[4], c6 = m64[5] ^ base[5], c7 = m64[6] ^ base[6], c8 = m64[7] ^ base[7];
    // Same recurrence as upstream, carried in a rolling window: gcc 13 -O3
    // vectorizes the array form without -fno-strict-aliasing and gets it wrong.
    {
        std::array<U64, 8> w;
        for (unsigned i = 0; i < 8; ++i)
            w[i] = m64[i];
        for (unsigned i = 8; i < 32; ++i) {
            const U64 next = gamma(w[0], w[4]) + gamma(w[1], w[5]) + gamma(w[2], w[6]) + gamma(w[3], w[7]);
            for (unsigned j = 0; j < 7; ++j)
                w[j] = w[j + 1];
            w[7] = next;
            m64[i] = next;
        }
    }
    for (unsigned i = 24; i < 32; ++i)
        m128[i] = U128(m64[i]);
    for (unsigned i = 32; i < 48; ++i)
        m128[i] = beta(m128[i - 8]) + beta(m128[i - 7]) + beta(m128[i - 4]) + beta(m128[i - 3]);
    for (unsigned i = 41; i < 48; ++i)
        m256[i] = U256(m128[i]);
    for (unsigned i = 48; i < 64; ++i)
        m256[i] = beta(m256[i - 7]) + beta(m256[i - 6]) + beta(m256[i - 2]) + beta(m256[i - 1]);
    for (unsigned i = 0; i < 32; ++i) {
        auto powers = exp64.pair(c1 ^ sig0(c2), c3 ^ sig1(c4));
        auto d1 = powers.first + ror<7>(c6) + rol<13>(c5);
        auto d2 = powers.second + ch(c5, c6, c7) + maj(c1, c4, c8);
        auto d3 = c8 + Sig0(c7) + round64[i];
        auto d4 = c5 + Sig1(c1) + d1 + m64[i] + t.pow64(d3);
        c8 = c7 + U64(folded);
        c7 = c6 + d1 + sig0(M64::mul(d1, d3));
        c6 = c5 + sig1(d2 ^ d3);
        c5 = c4;
        c4 = c3 + d4;
        c3 = c2;
        c2 = c1 ^ d3;
        c1 = gamma(d1, d2) + (d3 ^ d4) + beta(M64::mul(d2, d4));
    }
    U128 f1, f2, f3, f4;
    f1.v = {c5.v[0], c1.v[0]};
    f2.v = {c6.v[0], c2.v[0]};
    f3.v = {c7.v[0], c3.v[0]};
    f4.v = {c8.v[0], c4.v[0]};
    for (unsigned i = 0; i < 16; ++i) {
        auto powers = exp128.pair(f1 ^ beta(f3), f2 ^ beta(f4));
        auto a = powers.first + sig0(f2 ^ f4) + ch(f2, f3, f4);
        auto b = powers.second + sig1(f1 ^ f3) + maj(f1, f2, f3);
        auto c = rol<29>(~f1) + ror<7>(~f2) + f3 + (~f4) + m128[32 + i] + t.pow128(f3);
        auto d = rol<29>(~f3) + ror<7>(f4) + f2 + (~f1) + round128[i];
        f4 = f3 + a;
        f3 = f2;
        f2 = f1 + c + beta(d);
        f1 = b + Sig0(a ^ c ^ d);
    }
    U256 h1, h2;
    h1.v = {f3.v[0], f3.v[1], f1.v[0], f1.v[1]};
    h2.v = {f4.v[0], f4.v[1], f2.v[0], f2.v[1]};
    for (unsigned i = 0; i < 16; ++i) {
        auto powers = exp256.pair(rol<11>(h1) ^ h2, h1 ^ beta(~h2));
        auto j1 = powers.first + beta(h1 ^ h2);
        auto j2 = powers.second + gamma(h1, h2);
        powers = exp256.pair(j1, j2);
        auto j3 = gamma(j1, j2) + powers.first + round256[i];
        auto j4 = gamma(j3, beta(h2)) + powers.second + m256[48 + i] + ch(j1, j2, j3);
        const std::pair<U256, U256> p5 = t.curve[0](h1);
        const std::pair<U256, U256> p6 = t.curve[1](h2);
        const std::pair<U256, U256> p7 = t.curve[2](j1);
        const std::pair<U256, U256> p8 = t.curve[3](j3);
        const U256 j5 = p5.first, j6 = p5.second;
        const U256 j7 = p6.first, j8 = p6.second;
        const U256 j9 = p7.first, j10 = p7.second;
        const U256 j11 = p8.first, j12 = p8.second;
        h2 = h1 + gamma(j1, j3) + maj(j2, j3, j4) + j5 + j8 + ch(j1, j6, j7) + beta(j10) + j11;
        h1 = beta(j2) + gamma(j3, j4) + Sig1(M256::mul(j1, j2)) + maj(j7, j6, j5) + Sig0(j9) + j12;
    }
    auto u1 = h1, u2 = h2 + U256(folded);
    for (const auto& fc : final) {
        auto powers = t.pow256.pair(u1, u2);
        auto k1 = powers.first + beta(u2);
        auto k2 = powers.second + gamma(u1, u2) + ch(k1, u2, u1);
        auto k3 = inverse256(k2) + beta(u1) + beta(u2 ^ k1 ^ fc);
        u2 = (k1 ^ u1) + maj(k1, k2, u2) + beta(k3);
        u1 = beta(k1) + k2;
    }
    Digest result;
    (u1 + beta(u2)).store(result.data());
    return result;
}
} } // namespace bc3::detail

namespace bc3 {
static const char* domain = "BC3Hash-BlockHash-Algorithm/BitcoinIII-PoW/2026";
// Derived by the exact hashlib formulas in the authoritative bc3hash.py.
constexpr std::array<std::uint8_t, 8> person_s{{0x0a, 0x20, 0xe8, 0x11, 0x61, 0x09, 0x08, 0xba}};
constexpr std::array<std::uint8_t, 16> person_b{{0x1e, 0x80, 0xf2, 0xfd, 0xdc, 0x58, 0x18, 0xd6, 0xfe, 0x9b, 0x58, 0x1e, 0x3b, 0xd4, 0x93, 0x0b}};
template <class H>
void tag(H& h, const char* suffix)
{
    h.update(domain, std::strlen(domain));
    h.update(suffix, std::strlen(suffix));
}
struct State {
    standard::Sha3 sha3_512{512}, sha3_384{384};
    standard::Sha512 sha512;
    standard::Ripemd160 ripemd;
    standard::Blake2s blake_s{person_s};
    standard::Blake2b blake_b{person_b};
    State()
    {
        tag(sha3_512, "/SHA3-512");
        tag(sha3_384, "/SHA3-384");
        tag(sha512, "/SHA-512");
        tag(ripemd, "/RIPEMD-160");
        tag(blake_s, "/BLAKE2s");
        tag(blake_b, "/BLAKE2b");
    }
    void update(const void* data, std::size_t n)
    {
        if (n && !data) throw std::invalid_argument("Null BC3 input");
        sha3_512.update(data, n);
        sha3_384.update(data, n);
        sha512.update(data, n);
        ripemd.update(data, n);
        blake_s.update(data, n);
        blake_b.update(data, n);
    }
    Digest finish()
    {
        Block512 preimage;
        sha3_512.finish(preimage.data());
        const Digest mix = detail::mix512(preimage.data(), 0);
        std::array<std::uint8_t, 48> s384;
        sha3_384.finish(s384.data());
        const auto s512 = sha512.finish();
        const auto r160 = ripemd.finish();
        const auto bs = blake_s.finish();
        const auto bb = blake_b.finish();
        standard::Sha3 final{256};
        tag(final, "/SHA3-256");
        final.update(s384.data(), s384.size());
        final.update(mix.data(), mix.size());
        final.update(s512.data(), s512.size());
        final.update(r160.data(), r160.size());
        final.update(bs.data(), bs.size());
        final.update(bb.data(), bb.size());
        Digest output;
        final.finish(output.data());
        return output;
    }
};
Digest bc3hash(const void* data, std::size_t n)
{
    State state;
    state.update(data, n);
    return state.finish();
}
} // namespace bc3

extern "C" {
/* Call before bc3_hash_init_cxx(); 0 = the default. -1 once the tables
 * exist, so the gate cannot mistake an ineffective request for success. */
int bc3_hash_set_window(unsigned window)
{
    if (bc3::detail::tables_frozen)
        return -1;
    bc3::detail::curve_window = window ? window : BC3_CURVE_WINDOW;
    return 0;
}

/* Bytes the four curve tables occupy at a given window, 0 outside the range
 * where the shifts below are defined. Kept here rather than in the C gate so
 * the sizing formula cannot drift from what the tables really allocate. */
std::uint64_t bc3_hash_table_bytes(unsigned window)
{
    if (window < 2 || window > 31)
        return 0;
    const unsigned digits = (256 + window - 1) / window;
    const std::uint64_t entries = (1ULL << window) - 1;
    const unsigned rest = 256 - window * (digits - 1);
    const std::uint64_t last = (1ULL << rest) - 1;
    return 4ULL * ((std::uint64_t)(digits - 1) * entries + last)
           * sizeof(secp256k1_pubkey);
}

/* The window the tables will actually be built at, default included. */
unsigned bc3_hash_get_window(void)
{
    return bc3::detail::curve_window;
}

int bc3_hash_init_cxx(void)
{
    try {
        (void)bc3::detail::tables();
        bc3::detail::tables_frozen = true;
        return 0;
    } catch (const std::bad_alloc&) { return -1; }        /* secp context / table alloc */
    catch (const std::exception&) { return -2; }         /* curve constant or point op */
    catch (...) { return -3; }
}
int bc3_hash_cxx(const void* data, std::uint32_t len, unsigned char* out)
{
    if (!out || (len && !data)) return -1;
    try {
        const bc3::Digest d = bc3::bc3hash(data, len);
        for (std::uint32_t i = 0; i < 32; ++i) out[i] = d[i];
        return 0;
    } catch (...) { return -1; }
}
}
