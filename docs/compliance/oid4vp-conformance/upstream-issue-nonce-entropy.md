# VP1FinalEnsureMinimumNonceEntropy warns on most 128-bit base64url nonces

*Draft issue for the OpenID Foundation conformance suite tracker
(<https://gitlab.com/openid/conformance-suite/-/issues>). Written by the HelixIAM maintainers after a self-run of
the verifier plans; not yet filed.*

## Summary

In the OpenID4VP 1.0 Final verifier tests, `VP1FinalEnsureMinimumNonceEntropy` (requirement `OID4VP-1FINAL-5.2`)
reports a WARNING for most nonces made of 16 random bytes, base64url-encoded without padding. That is exactly 128
bits, the amount the condition's own message recommends (OpenID4VP PR #722). The condition's comment says its
96-bit threshold is meant to avoid "false-positive failures on legitimate 128-bit nonces". For this encoding it does
not avoid them.

## Version

Suite 5.3.3, revision `f0133e9` (master, 2026-10-14). Plans `oid4vp-1final-verifier-haip-test-plan` and
`oid4vp-1final-verifier-test-plan`, module `oid4vp-1final-verifier-happy-flow` (all variants).

## What we observed

The verifier's nonce is `SecureRandom` 16 bytes → base64url, 22 characters. Example from a run:

```
value: "X5wT39KNf8YtAdpvTOuywA"   expected: 96.0   actual: 92.10749561002051   -> WARNING
```

The warning appeared in 27 of 28 happy flows of one run.

## Why

`AbstractEnsureMinimumEntropy` does not measure the entropy of the source. It computes the Shannon entropy of the
string's own character frequencies and multiplies it by the length:

```
entropy = H(character frequencies of s) * s.length()
```

For a string of n characters, H is at most log2(n), and it reaches that only when no character repeats. So a
22-character string can score at most 22 × log2(22) ≈ 98.1 under this formula, whatever its source. One repeated
character leaves it at about 96.1; two repeats (or one character three times) push it below 96. With 22 characters
drawn from a 64-symbol alphabet, repeats are the normal case (birthday bound).

## Simulation

We fed 100,000 nonces of each size, from a CSPRNG and base64url-encoded without padding, through the same formula:

| Random bytes | Characters | Mean score | Share scoring > 96 (passes) |
|---:|---:|---:|---:|
| 16 (128 bits) | 22 | 91.3 | 10.7 % |
| 24 (192 bits) | 32 | 145.9 | 100 % |
| 32 (256 bits) | 43 | 208.5 | 100 % |

So about 89 % of correct 128-bit nonces are flagged, and the outcome depends on chance rather than on the verifier.

Reproduction (Node.js):

```js
const c = require('crypto');
const H = s => { const m = {}; for (const ch of s) m[ch] = (m[ch] || 0) + 1;
  return -Object.values(m).reduce((h, k) => h + (k / s.length) * Math.log2(k / s.length), 0) * s.length; };
let pass = 0; const N = 100000;
for (let i = 0; i < N; i++) if (H(c.randomBytes(16).toString('base64url')) > 96) pass++;
console.log(`${(100 * pass / N).toFixed(1)} % of 128-bit base64url nonces score above 96`);
```

## Suggested fix

Any one of these would stop the false positives:

1. **Estimate from the alphabet, not from character frequencies.** Detect the encoding (for example, base64url
   `[A-Za-z0-9_-]` gives 6 bits per character, hex gives 4) and estimate `length × bits per character`. For a
   22-character base64url string that is 132 bits. Keep the Shannon check as a separate signal for obviously
   non-random values, such as runs of one character or very low per-character entropy.
2. **Use a threshold this formula can reach.** For example, require at least 22 base64url characters (or 32 hex
   characters) and a per-character entropy above a small floor, instead of a fixed 96-bit product.
3. **Account for the formula's ceiling.** If the product is kept, compare it with a threshold below
   `n × log2(n)` for the given length, or lower the threshold for short strings.

Option 1 matches the intent of the message ("at least 128 bits") most closely.

The same base class is used by `EnsureMinimumNonceEntropy` and `EnsureMinimumClientSecretEntropy`, so other plans
may show the same behaviour for short base64url values.
