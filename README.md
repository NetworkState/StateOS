
## State Operating System
---

### A decentralized blockchain-based storage and distribution of state.
---

*under development, not ready for use.*

#### Portable Runtime.

- Written in Modern C (C++ without OOP, STL, or exceptions)
- No dependencies on 3rd party software.
- Lock free. Cognizant of branch free optimizations.
- Stack-based, relatively static memory allocation.  No GC or ref counting.
- Extensive use of SIMD, AVX512 (no float).
- Crypto library optimized with CPU extensions.
- TPM-centric ECDSA and X509.
- Portable to user mode, kernel mode, and DPUs.
- Zero trust, self-configurable through certificates.
- TPM attested, sealed, execution environment.  


#### Network Stack.

- Native, self-contained, implementation of network protocols.
- QUIC for signaling and data transport.
- QUIC based messaging system.
- HTTP/3 with QPACK optimizations.
- WebRTC, SRTP, SDP, WHIP, RTMP, RTSP, and related streaming protocols.
- HTTP/1.1 for compatibility.
- On-demand multicast data paths with QOS for synchronization.
- Support for Media Over QUIC (MOQ).

#### Blockchain.

- Private blockchain, optimized for enterprise use.
- No mining, proof of stake, or proof of concept.
- Blocks added in a deterministic cooperative algorithm.
- Stores object data as immutable units.
- API gateways to assemble and fragment structured data.
- Supports JSON/XML, media containers (MP4), and Office documents.
