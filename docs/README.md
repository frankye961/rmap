# Documentation

Start with [the project overview](../README.md) for purpose, building and quick
commands. rmap is a networking and cybersecurity research project; observations,
uncertainty and model interpretation remain distinct.

## User guides

- [Usage and CLI reference](usage.md): targets, ports, modes, defaults and troubleshooting.
- [Reading results](results.md): state semantics, banner previews and uncertainty.
- [Service identification](service-identification.md): candidate probes and their limits.
- [Recorded console example](examples.md): anonymized scan and historical AI output.
- [AI integration](ai-integration.md): environment settings, prompts and bounded research.

## Development and research

- [Architecture](architecture.md): control flow, models and evidence boundaries.
- [Project layout](project-layout.md): module map, constants and offline tests.
- [Research direction](research.md): reproducibility and later assessment work.
- [SYN versus ACK experiment](experiments/syn-vs-ack.md): question, hypothesis,
  controlled conditions and a results log awaiting measurements.
- [Original learning checklist](milestone-1.md): historical introductory tasks.

## Protocol learning guides

These guides explain the implementation and link to protocol specifications:

- [TCP SYN and low-level Rust networking](syn-learning-guide.md)
- [HTTPS identification](https-identification.md)
- [RPC portmapper NULL and DUMP](rpc-identification.md)
- [NFSv3 NULL identification](nfs-identification.md)
- [SMB2 NEGOTIATE identification](smb-identification.md)
