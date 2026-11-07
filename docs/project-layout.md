# Project layout and maintenance

rmap remains one Cargo binary crate. Modules group related responsibilities;
there is no workspace split or new runtime service.

## Source map

```text
src/
├── main.rs                     CLI → scan → measured report → optional AI
├── settings.rs                 Shared scan defaults and limits
├── cli/
│   ├── mod.rs                  Option state, duplicate checks, defaults
│   ├── config.rs               Validated CliConfig
│   ├── help.rs                 Help text derived from shared defaults
│   ├── ports.rs                Port and range parsing
│   └── targets.rs              IPv4/CIDR expansion and deduplication
├── model/
│   ├── mod.rs                  ScanMode, PortStatus, measured ScanResult
│   ├── ai.rs                   Interpretation, advisory and web evidence data
│   ├── rpc.rs                  Advertised RPC registrations
│   ├── service_information.rs  Parsed service identity data
│   ├── smb/{mod,header,body}.rs Structured SMB2 request data
│   └── syn.rs                  Original probe and parsed reply data
├── mapper/
│   ├── service_information.rs  Construct/apply parsed service data
│   └── syn.rs                  Map SYN measurements into ScanResult
├── scan/
│   ├── mod.rs                  Validate scan settings and dispatch work
│   ├── worker.rs               Bounded tasks and ordered results
│   ├── resources.rs            Descriptor budgeting
│   ├── identify.rs             Passive SSH/HTTP/FTP/SMTP recognition
│   ├── http.rs                 HTTP/HTTPS HEAD probes and header parsing
│   ├── nfs.rs                  NFSv3 NULL using shared RPC exchange
│   ├── udp.rs                  UDP probe and conservative classification
│   ├── tcp/
│   │   ├── mod.rs              Initial connection measurement
│   │   ├── banner.rs           Passive bounded reads and stop reasons
│   │   └── service.rs          Probe selection and evidence application
│   ├── rpc/
│   │   ├── mod.rs              Portmapper NULL/DUMP entry points
│   │   ├── constants.rs        RPC values and independent reply/list bounds
│   │   ├── request.rs          XDR request encoding
│   │   ├── record.rs           Framing and bounded fragment reassembly
│   │   ├── reply.rs            Envelope validation and DUMP list parsing
│   │   └── transport.rs        Connection, writing and reading
│   ├── smb/
│   │   ├── mod.rs              Candidate selection and shared client GUID
│   │   ├── constants.rs        SMB2 wire values and reply limit
│   │   ├── request.rs          Typed request building and LE byte encoding
│   │   ├── reply.rs            Negotiation validation and evidence mapping
│   │   └── transport.rs        Direct TCP framing and bounded I/O
│   └── syn/
│       ├── mod.rs              Probe preparation and orchestration
│       ├── constants.rs        Shared header sizes, flags and cleanup bound
│       ├── packet.rs           Packet construction, parsing and checksums
│       ├── reply.rs            Reply matching, classification and cleanup
│       └── socket.rs           Raw socket setup and Tokio readiness
├── report/
│   ├── mod.rs                  Console reporting entry points
│   ├── branding.rs             Startup banner and Cargo version
│   ├── constants.rs            Layout widths and display/progress bounds
│   ├── measured.rs             Port rows, uncertainty notes, RPC tables
│   ├── ai.rs                   Separate interpretation and source display
│   └── progress.rs             Throttled stderr progress
├── ai/
│   ├── config.rs               Provider settings and local .env loading
│   ├── constants.rs            Session, prompt and web-evidence bounds
│   ├── prompt.rs               Observation/advisory formatting
│   ├── prompts/research.txt    Research instructions with bound placeholders
│   ├── service.rs              Rig/DeepSeek orchestration and error handling
│   ├── web.rs                  Brave search tool and retained evidence
│   └── retrieval.rs            Optional local advisory lookup
└── utils/banner.rs             Shared banner decoding, escaping, line iteration, version tokens
```

Each module directory also has a `mod.rs` declaring its children. Models hold
data; `ScanResult::new` centralizes empty evidence fields for each scan mode; reporting owns presentation; scanners collect measurements and service
evidence. AI is called by the application after the measured report, outside
the scanning engine.

## Where to change constants

| Concern | Location |
| --- | --- |
| Default timeout/concurrency, concurrency ceiling, target count | `src/settings.rs` |
| HTTP/HTTPS candidate ports | `src/scan/http.rs` |
| Passive banner byte/chunk bounds | `src/scan/tcp/banner.rs` |
| SSH identification-line length | `src/scan/identify.rs` |
| UDP response buffer | `src/scan/udp.rs` |
| Shared console byte-preview length | `src/utils/banner.rs` |
| Descriptor headroom | `src/scan/resources.rs` |
| RPC wire values, verifier bound, reply/list limits | `src/scan/rpc/constants.rs` |
| NFS program, version, candidate port | `src/scan/nfs.rs` |
| SMB wire values and reply limit | `src/scan/smb/constants.rs` |
| SYN sizes, flags, window and cleanup budget | `src/scan/syn/constants.rs` |
| Provider timeout, tokens, turns, observations and search bounds | `src/ai/constants.rs` |
| Local advisory file/record limits | `src/ai/retrieval.rs` |
| Console formatting and progress intervals | `src/report/constants.rs` |

Keep a value next to the domain that owns it. Different bounds can happen to
have the same number: RPC and SMB reply limits remain independent, as do AI
prompt truncation and console previews. Standard byte offsets, zero-filled
reserved fields, and arithmetic units can remain explicit where they describe
the wire format directly. Protocol identifiers and header sizes follow their
specifications; they are not performance knobs.

Help text uses the same scan-default constants as parsing. AI instructions and
tool descriptions insert the configured search budget rather than spelling out
a separate limit. Update the corresponding documentation when changing a
user-visible default or supported protocol.

## Tests and validation

Tests stay under `tests/cli`, `tests/scan`, `tests/report`, and `tests/ai`.
Source modules include them through `#[cfg(test)]` and `#[path]`, allowing tests
of private parsing and I/O helpers without making an external library API.
Protocol fixtures retain independently written wire values so that incorrect
production constants cannot automatically change the expected response bytes.

Run the commands in [the README](../README.md#development). Test streams and fake
probes exercise framing, deadlines, result preservation and task scheduling
without contacting a host or AI provider. Live interoperability and performance
remain separate controlled-lab work.
