# "CAN I have flag ?" Write-up

Author : Bruno LADERVAL @SOOBIK
www.soobik.com

## Summary

The challenge provided a Saleae logic capture of a single digital line and the following hint:

> “I CAN capture some signals from a device. But I CAN not make any sense of it. I heard that the protocol CAN have different versions. So the tooling CAN lie about the true data. CAN you decode the signals? Then you CAN get a flag.”

The main trap was that the signal was **not classic CAN at a single bitrate**.  
It was a **CAN FD frame stream using Bit Rate Switching (BRS)**, so a naive decoder configured for classic CAN or for a single constant bitrate would produce misleading results.

The recovered flag was:

```text
DHM{CAN_[REDACTED]}
```

---

## Initial assessment

The original file was a native Saleae `.sal` capture, which is not ideal for custom parsing.  
To analyze it properly, the capture was exported as CSV from Saleae.

The exported CSV contained:

- timestamps,
- logic levels,
- digital transitions for one channel.

That format was sufficient to reconstruct the bus waveform.

---

## Key observation

The challenge statement strongly suggested that:

1. the signal was related to **CAN**,
2. the decoder could be wrong because of a **protocol/version mismatch**.

That immediately raised the possibility of:

- **standard CAN vs CAN FD**,
- or a **bitrate mismatch**,
- or both.

When measuring run lengths in the transition stream, two timing regions appeared:

- an initial region compatible with **500 kbit/s**  
  → bit time ≈ **2 µs**
- a later region compatible with **1 Mbit/s**  
  → bit time ≈ **1 µs**

This is characteristic of **CAN FD with BRS enabled**:

- arbitration phase at the nominal bitrate,
- data phase at a higher bitrate.

That explains why a simplistic CAN decoder would “lie” about the payload.

---

## Methodology

### 1. Segment the capture into candidate frames

The CSV was split into bursts separated by long idle gaps.  
Each burst was treated as a candidate CAN frame.

### 2. Reconstruct the bitstream

The digital transitions were converted into level runs `(level, duration)`.  
Those runs were then expanded into bits using two different bit times:

- **2 µs per bit** during the arbitration/header portion,
- **1 µs per bit** during the payload portion.

### 3. Remove CAN bit stuffing

CAN and CAN FD use bit stuffing.  
After five consecutive identical bits, one complementary stuff bit is inserted.  
Those bits were removed before frame parsing.

### 4. Parse the CAN FD structure

The decoded frames were interpreted as **standard 11-bit CAN FD frames**:

- SOF
- 11-bit identifier
- control bits
- FDF
- BRS
- ESI
- DLC
- data field

The relevant frames consistently decoded as **CAN FD with BRS enabled**.

### 5. Extract text fragments from payloads

The payloads of the useful frames contained ASCII text fragments that described how to build the flag.

One relevant ID repeatedly carried the message fragments.

---

## Extracted content

The decoded messages included the following fragments:

- `Hello, let me tell you a story about a flag`
- `First there comes the preamble \`DHM{\``
- `Then it starts with \`[REACTED]?_\``
- `In the middle comes \`[REDACTED]_CAN!_\``
- `Finally there is \`[REDACTED]_CAN\``
- `And it ends as you would expect \`}\``

By concatenating those parts, the final flag is obtained.

---

## Final flag

```text
DHM{[REDACTED]}
```

---

## Why this challenge works

This challenge is effective because the raw signal really does look like CAN, but the tooling can mislead the analyst if the protocol version is assumed incorrectly.

The important lesson is:

- **classic CAN assumptions are not always valid**,
- **CAN FD changes the decoding conditions**,
- and **bitrate switching must be handled explicitly**.

If the analyzer is configured for a single bitrate, the arbitration may look correct while the data field becomes garbage.

---

## Takeaways

- Always validate the physical timing before trusting a decoder.
- When a protocol has multiple variants, check whether the capture matches the expected version.
- In CAN-related challenges, **CAN FD + BRS** is a natural source of parser failure.
- Exporting the signal to a simple format such as CSV is often the fastest way to regain control over the analysis.

---

## Minimal conclusion

This challenge was solved by:

1. exporting the Saleae capture to CSV,
2. reconstructing the signal manually,
3. recognizing **CAN FD with bitrate switching**,
4. parsing the payload correctly,
5. rebuilding the flag from the extracted ASCII fragments.


