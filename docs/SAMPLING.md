# Exact compression and bounded finite Gaussian sampling

All statements in this document first use independent ideal random bits. The
implementation obtains bits from OpenSSL `RAND_priv_bytes`; a standard CSPRNG
hybrid adds the relevant computational distinguishing advantage. Deterministic
ChaCha20 test streams are not a security mechanism.

## Exact integer quantizer

For a in {0,...,q-1}, set j=floor(Ma/q), r=Ma mod q and D=8qM. Start with
L=8M(q-r), R=8Mr. The unwrapped support and integer masses are:

- If 2r<M: t=M-2r; support (j-1,j,j+1), masses (t^2,L-2t^2,R+t^2).
- If 2(q-r)<M: t=M-2(q-r); support (j,j+1,j+2), masses (L+t^2,R-2t^2,t^2).
- Otherwise: support (j,j+1), masses (L,R).

Sample a uniform integer below D by rejection, choose its cumulative interval,
then reduce the selected integer modulo M. Under q<2^50 and M<=q, the largest
intermediate here fits unsigned 128-bit arithmetic. The common denominator is
retained; there is no floating-point probability normalization.

These masses integrate stochastic rounding after a uniform dither in [-1/2,1/2).
For a reconstructed unwrapped grid value q*k/M, conditional error has mean zero
and second moment at most q^2/(4M^2)+1/12. A uniform coefficient modulo q maps to
exactly uniform modulo M even if M does not divide q. This is a statement about
uniform input, not that actual ciphertext coefficients are statistically uniform.
Their pseudorandomness remains a computational security property.

The independent Python verifier integrates the triangular rounding kernel with
`Fraction`, rather than reusing these polynomial weight formulas. It checks all
2,016 pairs 2<=M<=q<=64 and 87,360 inputs. C++ also checks 1,005 main-modulus inputs.
Exhaustion of small moduli does not itself prove the general formula; the formula
and analytical properties are the ones specified in the paper.

## Small-width discrete Gaussians

For s=17 or 32, truncate D_Z,s to the integer interval [-12s,12s]. The distribution
uses mass exp(-pi*x^2/s^2). A 256-bit integer selects an inverse-CDF interval with
threshold floor(2^256 F(x)). The half-Gaussian proposal on {0,...,384} at s=32 is
constructed in the same way. Thresholds, including ties and repeated thresholds,
are integers. `upper_bound` implements the correct interval convention.

Threshold generation uses outward-rounded 896-bit integer intervals. Pi is bounded
by Machin's identity and alternating arctangent series. Exponentials use range
reduction to [0,1/8], alternating Taylor bounds and outward-rounded squaring.
CDF and survival-function bounds are intersected. The generator stops with an
error if a threshold is not uniquely certified. All committed thresholds are
regenerated during self-check; they are not decimal approximations silently rounded
into integer tables. The manifest records the header's SHA-256 digest.

For m outcomes, replacing an exact finite CDF by floor thresholds changes total
variation distance by at most (m-1)*2^-256. Here m<=769. Using Z_s>=s and the
Gaussian integral tail bound, the removed probability beyond 12s is less than
exp(-144*pi)/(12*pi), hence below 2^-650. A convenient bound on each small-width
sample is therefore 2^-240, with substantial slack.

## Large-width discrete Gaussians

Every large width in the evaluated presets is a multiple of 32. Write s=32t.
Draw k from the finite half-Gaussian at width 32, draw j uniformly in [0,t), and
draw a fair sign. Set x=k*t+j; reject negative zero. Accept this proposal with

    exp(-pi*(2*k*t*j+j^2)/(1024*t^2)).

Ignoring finite numerical approximation, the accepted signed mass is proportional
to exp(-pi*x^2/s^2) on |x|<=385t-1. This follows because the proposal mass is
proportional to exp(-pi*k^2/1024), so multiplication by the displayed acceptance
factor yields the desired exponent exactly. No continuous normal approximation
or rounding of a floating-point Gaussian is involved.

With Z_half,32<17 and the truncated Z_s>31t, the ideal proposal acceptance is
greater than 31/34. This lower bound prevents rejection from amplifying a small
sampling error into an uncontrolled distance.

The acceptance comparison draws a full 256-bit uniform integer. Most comparisons
are resolved using an outward-rounded 64-bit enclosure. Unresolved comparisons
are refined with a 384-bit enclosure. The lower endpoint is rounded down to the
256-bit grid. The implementation checks an enclosure-width ceiling of 2^32 units
at precision 384. This contributes less than 2^-352 before 256-bit rounding, so
the acceptance-probability discrepancy is below 2^-255.

For completeness, the interval-width ceiling is deliberately loose. The exponent
is below 3, so at most five range-reduction squarings occur. After reduction the
argument is at most 1/8. At precision 384, fewer than 128 Taylor terms suffice.
Integer rounding adds at most one unit per multiplication/division endpoint;
propagating interval widths through the alternating sum and five squarings gives
a bound far below 2^32. The executable check fails closed rather than using an
uncertified probability if this ceiling is ever violated. Independent Python
interval computations cross-check all exported endpoint cases, and unit tests
force both outcomes of the normally rare refinement branch.

The half-Gaussian proposal has distance at most 385*2^-256 plus its tail.
Conditioning on acceptance with probability >31/34 increases the joint
proposal/acceptance error by at most 2/(31/34). Combining proposal discretization,
acceptance rounding and the omitted target tail remains below 2^-240 per accepted
large-width sample. This conservative common bound is used for every Gaussian
coefficient in the implementation.

## Whole-encryption statistical budget

The main instance samples 1,172,736 Gaussian coefficients. Its distance from the
ideal Gaussian encryption experiment is bounded by

    1,172,736 * 2^-240 < 2^-219.

This is a distributional coupling bound, not an empirical failure rate. It applies
regardless of the later deterministic arithmetic and randomized compression.
For many encryptions, sum the respective sample counts. The correctness bound
for the implementation is the ideal paper bound plus this sampling distance.
The security hybrid likewise includes the sampling distance, in addition to the
paper's reduction terms and the CSPRNG computational advantage.

`results/parameters.json` reports BOTH ideal and implementation bounds. In
particular, the extremely small ideal bounds of some two-coordinate controls
are dominated by the finite sampler's distance. They are not advertised as the
implementation's failure probability. The main implementation retains a bound
below 2^-143 in the ideal-bit model.

## What the tests do not establish

Moment/frequency smoke tests can detect gross implementation errors, but cannot
measure a probability such as 2^-143. The tail bound, interval certificates and
composition argument supply that evidence. None of these tests establishes the
computational hardness of Module-LWE or resistance to side-channel attacks.
