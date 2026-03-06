#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CAN FD decoder for the challenge "CAN I have flag".

Capture exported from Saleae as CSV.

Expected input:
    python3 extract.py digital.csv

Assumptions validated on this capture:
- Single digital signal representing the CAN bus level
- Arbitration bitrate: 500 kbit/s  -> 2 us per bit
- Data bitrate:        1 Mbit/s    -> 1 us per bit
- Standard 11-bit CAN ID
- CAN FD frame with BRS enabled
- No physical errors in the capture

Author : Bruno LADERVAL @SOOBIK
www.soobik.com
"""

from __future__ import annotations

import csv
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


# =============================================================================
# Configuration
# =============================================================================

IDLE_GAP_S = 50e-6          # Gap used to separate independent frame bursts
ARB_BIT_S = 2e-6           # 500 kbit/s
DATA_BIT_S = 1e-6          # 1 Mbit/s

# Search bounds for the approximate number of arbitration bits before the BRS area
ARB_BITS_SEARCH_MIN = 16
ARB_BITS_SEARCH_MAX = 32

# Minimum printable fragment size to keep
MIN_ASCII_LEN = 6


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class TransitionCapture:
    times: List[float]
    levels: List[int]


@dataclass
class Run:
    level: int
    duration: float


@dataclass
class DecodedFrame:
    segment_index: int
    polarity: str
    arb_prefix_bits: int
    identifier: int
    dlc: int
    payload: bytes
    raw_destuffed_bits: List[int]

    @property
    def ascii_payload(self) -> str:
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in self.payload)


# =============================================================================
# CSV loading and segmentation
# =============================================================================

def load_saleae_csv(path: str) -> TransitionCapture:
    times: List[float] = []
    levels: List[int] = []

    with open(path, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)

        if len(header) < 2 or "Time" not in header[0]:
            raise ValueError("Unexpected Saleae CSV format")

        for row in reader:
            if not row:
                continue
            times.append(float(row[0]))
            levels.append(int(row[1]))

    if len(times) < 2:
        raise ValueError("CSV is empty or incomplete")

    return TransitionCapture(times=times, levels=levels)


def split_segments(capture: TransitionCapture) -> List[Tuple[int, int]]:
    """
    Split the transition stream into candidate frame segments.

    Each segment is represented as a pair (start_index, end_index), where the
    actual runs are between times[i] and times[i+1] for i in [start_index, end_index].
    """
    times = capture.times
    segments: List[Tuple[int, int]] = []
    start = 1

    for i in range(len(times) - 1):
        if (times[i + 1] - times[i]) > IDLE_GAP_S:
            if i >= start:
                segments.append((start, i))
            start = i + 1

    if start < len(times) - 1:
        segments.append((start, len(times) - 2))

    return segments


def segment_to_runs(capture: TransitionCapture, start: int, end: int) -> List[Run]:
    runs: List[Run] = []
    for i in range(start, end + 1):
        runs.append(
            Run(
                level=capture.levels[i],
                duration=capture.times[i + 1] - capture.times[i],
            )
        )
    return runs


# =============================================================================
# Bit reconstruction
# =============================================================================

def build_bits_from_runs_with_switch(
    runs: List[Run],
    arbitration_prefix_bits: int,
    arb_bit_s: float = ARB_BIT_S,
    data_bit_s: float = DATA_BIT_S,
) -> List[int]:
    """
    Reconstruct a bitstream from level runs.

    The first 'arbitration_prefix_bits' are sampled at arb_bit_s.
    The remainder is sampled at data_bit_s.

    Since runs do not necessarily align to bit boundaries in a generic way, this
    function expands each run into a rounded number of equal bits. For this CTF
    capture, that model is sufficient.
    """
    bits: List[int] = []
    bits_emitted = 0

    for run in runs:
        remaining_duration = run.duration

        while remaining_duration > 0:
            current_bit_s = arb_bit_s if bits_emitted < arbitration_prefix_bits else data_bit_s

            # Emit at least one bit for the current chunk
            nbits = max(1, int(round(remaining_duration / current_bit_s)))

            # For runs crossing the bitrate switch, emit only the part that belongs
            # to the current timing region, then continue with the new region.
            if bits_emitted < arbitration_prefix_bits:
                until_switch = arbitration_prefix_bits - bits_emitted
                if nbits > until_switch:
                    nbits = until_switch

            bits.extend([run.level] * nbits)
            emitted_duration = nbits * current_bit_s
            remaining_duration -= emitted_duration
            bits_emitted += nbits

            # Prevent tiny negative floating-point residue from looping forever
            if remaining_duration < 0 and abs(remaining_duration) < 1e-12:
                remaining_duration = 0.0

            # Failsafe against pathological rounding drift
            if nbits <= 0:
                break

    return bits


def destuff_can(bits: List[int]) -> List[int]:
    """
    Remove CAN bit stuffing.

    Rule:
    after five consecutive identical bits, the next bit should be a stuffed
    complement bit and must be removed.
    """
    if not bits:
        return []

    out = [bits[0]]
    last = bits[0]
    same_count = 1
    i = 1

    while i < len(bits):
        b = bits[i]

        if same_count == 5:
            # Stuff bit expected here
            if b != last:
                i += 1
                same_count = 0
                continue
            # If not complementary, keep going without removing anything.
            # This makes the decoder more tolerant to slight alignment errors.

        out.append(b)

        if b == last:
            same_count += 1
        else:
            last = b
            same_count = 1

        i += 1

    return out


def invert_bits(bits: List[int]) -> List[int]:
    return [1 - b for b in bits]


# =============================================================================
# CAN / CAN FD parsing helpers
# =============================================================================

def bits_to_int(bits: List[int]) -> int:
    value = 0
    for b in bits:
        value = (value << 1) | b
    return value


def dlc_to_payload_length_can_fd(dlc: int) -> Optional[int]:
    """
    CAN FD DLC mapping.
    """
    mapping = {
        0: 0,
        1: 1,
        2: 2,
        3: 3,
        4: 4,
        5: 5,
        6: 6,
        7: 7,
        8: 8,
        9: 12,
        10: 16,
        11: 20,
        12: 24,
        13: 32,
        14: 48,
        15: 64,
    }
    return mapping.get(dlc)


def bits_to_bytes(bits: List[int]) -> bytes:
    if len(bits) % 8 != 0:
        return b""
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(bits_to_int(bits[i:i + 8]))
    return bytes(out)


def parse_standard_can_fd_frame(destuffed_bits: List[int]) -> Optional[Tuple[int, int, bytes]]:
    """
    Parse a standard 11-bit CAN FD frame after destuffing.

    Expected field layout used here:
      SOF                 1
      ID                 11
      RRS / RTR substitute 1
      IDE                 1
      FDF                 1
      res                 1
      BRS                 1
      ESI                 1
      DLC                 4
      DATA             N*8
      CRC + delimiters... (ignored here)

    For the challenge we only need ID, DLC, and payload.

    Returns:
        (identifier, dlc, payload) or None if invalid.
    """
    idx = 0

    if len(destuffed_bits) < 24:
        return None

    sof = destuffed_bits[idx]
    idx += 1

    # SOF must be dominant (0) on the bus
    if sof != 0:
        return None

    identifier = bits_to_int(destuffed_bits[idx:idx + 11])
    idx += 11

    rrs = destuffed_bits[idx]
    idx += 1

    ide = destuffed_bits[idx]
    idx += 1

    fdf = destuffed_bits[idx]
    idx += 1

    res = destuffed_bits[idx]
    idx += 1

    brs = destuffed_bits[idx]
    idx += 1

    esi = destuffed_bits[idx]
    idx += 1

    dlc = bits_to_int(destuffed_bits[idx:idx + 4])
    idx += 4

    # We want CAN FD standard frames with bitrate switching.
    if ide != 0:
        return None
    if fdf != 1:
        return None
    if brs != 1:
        return None

    payload_len = dlc_to_payload_length_can_fd(dlc)
    if payload_len is None:
        return None

    payload_bit_len = payload_len * 8
    if len(destuffed_bits) < idx + payload_bit_len:
        return None

    payload_bits = destuffed_bits[idx:idx + payload_bit_len]
    payload = bits_to_bytes(payload_bits)

    if len(payload) != payload_len:
        return None

    return identifier, dlc, payload


# =============================================================================
# Candidate search
# =============================================================================

def score_payload(payload: bytes) -> int:
    """
    Score how "text-like" a payload is.
    """
    if not payload:
        return 0

    printable = sum(1 for b in payload if 32 <= b <= 126)
    letters = sum(1 for b in payload if chr(b).isalnum() or chr(b) in b"_{}!?',.- ")
    return printable * 2 + letters


def try_decode_segment(
    runs: List[Run],
    segment_index: int,
) -> List[DecodedFrame]:
    """
    Search plausible configurations for one segment:
    - normal or inverted polarity
    - arbitration prefix length around the expected CAN FD header size
    """
    candidates: List[DecodedFrame] = []

    for polarity_name, polarity_transform in [
        ("normal", lambda x: x),
        ("inverted", invert_bits),
    ]:
        for arb_prefix_bits in range(ARB_BITS_SEARCH_MIN, ARB_BITS_SEARCH_MAX + 1):
            bits = build_bits_from_runs_with_switch(
                runs=runs,
                arbitration_prefix_bits=arb_prefix_bits,
            )
            bits = polarity_transform(bits)
            destuffed = destuff_can(bits)
            parsed = parse_standard_can_fd_frame(destuffed)

            if parsed is None:
                continue

            identifier, dlc, payload = parsed

            # Keep only frames with meaningful payload
            if score_payload(payload) <= 0:
                continue

            candidates.append(
                DecodedFrame(
                    segment_index=segment_index,
                    polarity=polarity_name,
                    arb_prefix_bits=arb_prefix_bits,
                    identifier=identifier,
                    dlc=dlc,
                    payload=payload,
                    raw_destuffed_bits=destuffed,
                )
            )

    # Sort candidates by how text-like they are
    candidates.sort(
        key=lambda frame: (
            score_payload(frame.payload),
            len(frame.payload),
        ),
        reverse=True,
    )

    # De-duplicate identical decodes
    unique: List[DecodedFrame] = []
    seen = set()
    for frame in candidates:
        key = (frame.identifier, frame.dlc, frame.payload)
        if key not in seen:
            seen.add(key)
            unique.append(frame)

    return unique


# =============================================================================
# Text extraction and flag reconstruction
# =============================================================================

def extract_ascii_fragments(frames: List[DecodedFrame]) -> List[str]:
    fragments: List[str] = []

    for frame in frames:
        text = frame.payload.decode("ascii", errors="ignore")
        printable_chunks = re.findall(rf"[ -~]{{{MIN_ASCII_LEN},}}", text)
        for chunk in printable_chunks:
            cleaned = chunk.strip()
            if cleaned:
                fragments.append(cleaned)

    # Keep order while removing duplicates
    seen = set()
    unique: List[str] = []
    for frag in fragments:
        if frag not in seen:
            seen.add(frag)
            unique.append(frag)

    return unique


def rebuild_flag_from_fragments(fragments: List[str]) -> Optional[str]:
    """
    Rebuild the flag from the textual fragments embedded in the CAN FD payloads.
    """
    joined = " ".join(fragments)

    parts: List[str] = []

    m = re.search(r"preamble [`']?(DHM\{)[`']?", joined)
    parts.append(m.group(1) if m else "DHM{")

    m = re.search(r"starts with [`']?([^`']+)[`']?", joined)
    if m:
        parts.append(m.group(1))

    m = re.search(r"middle comes [`']?([^`']+)[`']?", joined)
    if m:
        parts.append(m.group(1))

    m = re.search(r"Finally there is [`']?([^`']+)[`']?", joined)
    if m:
        parts.append(m.group(1))

    if not parts:
        return None

    candidate = "".join(parts)
    candidate = candidate.replace("`", "").replace(" ", "")

    if not candidate.endswith("}"):
        candidate += "}"

    if candidate.startswith("DHM{") and candidate.endswith("}"):
        return candidate

    return None


# =============================================================================
# Main
# =============================================================================

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {Path(sys.argv[0]).name} digital.csv")
        sys.exit(1)

    capture = load_saleae_csv(sys.argv[1])
    segments = split_segments(capture)

    print(f"[+] Loaded {len(capture.times)} transitions")
    print(f"[+] Found {len(segments)} candidate segments")

    best_frames: List[DecodedFrame] = []

    for seg_index, (start, end) in enumerate(segments, 1):
        runs = segment_to_runs(capture, start, end)
        candidates = try_decode_segment(runs, seg_index)

        if not candidates:
            continue

        best = candidates[0]
        best_frames.append(best)

        print(
            f"[+] Segment {seg_index}: "
            f"polarity={best.polarity}, "
            f"arb_prefix_bits={best.arb_prefix_bits}, "
            f"id=0x{best.identifier:03X}, "
            f"dlc={best.dlc}, "
            f"payload={best.payload!r}"
        )

    if not best_frames:
        print("[-] No decodable CAN FD frames found")
        sys.exit(2)

    fragments = extract_ascii_fragments(best_frames)

    print("\n[+] Extracted text fragments:")
    for frag in fragments:
        print(f"    {frag}")

    flag = rebuild_flag_from_fragments(fragments)

    print("\n[+] Reconstructed flag:")
    if flag:
        print(flag)
    else:
        print("Could not reconstruct a flag")

    # Optional: show the likely message-carrying IDs
    ids = {}
    for frame in best_frames:
        ids.setdefault(frame.identifier, 0)
        ids[frame.identifier] += 1

    print("\n[+] Frame count by ID:")
    for identifier, count in sorted(ids.items()):
        print(f"    0x{identifier:03X}: {count}")


if __name__ == "__main__":
    main()