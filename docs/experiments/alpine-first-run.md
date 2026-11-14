# First lab qualification: Alpine target, SYN versus ACK

This is a procedure to follow, not a report of measured findings. Version 0.6.0
passes offline tests; these first runs check the instrument on your actual path.
Use the scanner machine and your separate Alpine home server. Keep AI disabled.

## 1. Record what you have before changing anything

On the Alpine target, run these read-only checks and save the output:

```sh
cat /etc/alpine-release
uname -a
command -v nft
command -v iptables
command -v awall
command -v python3
command -v tcpdump
```

A missing command is useful information. Installed tools alone do not identify
which manager controls the firewall. From a privileged shell, record the current
rules using `nft list ruleset` if nft is available and `iptables-save` if iptables
is available. If both exist, retain both snapshots and identify the manager before
editing either. Do not flush rules, disable the firewall, change SSH access, or
install a replacement firewall for this first qualification.

Write down the target's actual LAN IPv4 address, scanner IPv4 address, interfaces,
whether traffic crosses a router, and the service/firewall configuration. A home
server firewall is a valid controlled boundary; another filtering machine is not
required. Existing rules may prevent the control from working; investigate that
before treating it as a silently dropped experimental condition.

## 2. Prepare the scanner and a record directory

Build from the repository root and verify the binary without sending probes:

```bash
cargo build --release --offline --locked
./target/release/rmap --help
RECORD_DIR="$HOME/rmap-experiments/qualification-01"
mkdir -p "$RECORD_DIR"
git rev-parse HEAD > "$RECORD_DIR/revision.txt"
git status --short > "$RECORD_DIR/working-tree.txt"
git diff > "$RECORD_DIR/working-tree.patch"
rustc --version > "$RECORD_DIR/rust-version.txt"
```

The help banner should say `v0.6.0` and list `--ack`. Use this same binary for
both methods; an installed `rmap` may still be an older version. Record the exact
commands, target configuration and timestamps in the record directory. Keep raw
captures and private topology details outside source control.

## 3. Establish the listening control (C1)

Choose TCP port 18080 and verify that it is unused before starting a listener.
If Python 3 is already available, open a separate terminal on Alpine and run:

```sh
LAB_IP=192.0.2.10
LAB_DIR=$(mktemp -d)
python3 -m http.server 18080 --bind "$LAB_IP" --directory "$LAB_DIR"
```

Replace `192.0.2.10` with the Alpine machine's LAN address. Use an empty directory
so the test listener serves no personal files. Keep the terminal open and retain
its startup output. If Python is absent or the command fails, stop here and choose
a working lab listener before taking measurements. Python documents the port,
bind and directory options in its [HTTP server reference](https://docs.python.org/3/library/http.server.html).

Start a separate packet capture on each machine before probing. When tcpdump is
available, a privileged terminal can run:

```sh
tcpdump -i any -nn -s 0 -U -w qualification-01.pcap 'tcp port 18080 or icmp'
```

Use different capture filenames on the two machines and record their locations.
`any` can capture traffic on several interfaces; record the interface metadata
and account for duplicates. Prefer the actual path interface once identified.
Keep captures running during the pair, then stop with Ctrl+C and retain the
capture/drop statistics. Captures may contain unrelated ICMP; keep them private.
If capture tooling is unavailable, prepare it before claiming packet-level
qualification. No capture command or listener was run by the assistant.

On the scanner, replace the documentation address, then run the first attempt:

```bash
LAB_TARGET=192.0.2.10
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$RECORD_DIR/C1-pair01-syn.start.txt"
sudo ./target/release/rmap --syn --target "$LAB_TARGET" --ports 18080 --timeout-ms 1000 --concurrency 1 > "$RECORD_DIR/C1-pair01-syn.stdout.txt" 2> "$RECORD_DIR/C1-pair01-syn.stderr.txt"
SCAN_STATUS=$?
printf '%s\n' "$SCAN_STATUS" > "$RECORD_DIR/C1-pair01-syn.exit.txt"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$RECORD_DIR/C1-pair01-syn.finish.txt"
```

Wait at least one second, then run ACK:

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$RECORD_DIR/C1-pair01-ack.start.txt"
sudo ./target/release/rmap --ack --target "$LAB_TARGET" --ports 18080 --timeout-ms 1000 --concurrency 1 > "$RECORD_DIR/C1-pair01-ack.stdout.txt" 2> "$RECORD_DIR/C1-pair01-ack.stderr.txt"
SCAN_STATUS=$?
printf '%s\n' "$SCAN_STATUS" > "$RECORD_DIR/C1-pair01-ack.exit.txt"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$RECORD_DIR/C1-pair01-ack.finish.txt"
```

With listener and both probe paths permitted, the prediction is SYN `open` and
ACK `unfiltered`. Check captures for the outgoing SYN/ACK probes and corresponding
responses. The ACK reset must reverse both endpoints and have a sequence number
equal to the outgoing probe's acknowledgment number. Raw headers and correlation
numbers are not exported in the console report; captures retain that evidence.
Use raw sequence numbers in Wireshark (`tcp.seq_raw` and `tcp.ack_raw`), since
its displayed relative numbers can obscure the comparison. See the
[TCP field reference](https://www.wireshark.org/docs/dfref/t/tcp.html) and
[relative sequence number explanation](https://wiki.wireshark.org/TCP_Relative_Sequence_Numbers).

A privilege/setup failure is not filtering. If results differ from the prediction,
record the actual result and investigate captures and existing rules. Do not
change an observation to fit the expected table.

Exit status 2 means CLI validation failed; 1 means a scan-level failure such as
missing raw-socket privileges. Status 0 means processing completed; individual
probe failures can still be `undetermined` in a completed report. Inspect both
stdout and stderr rather than treating status 0 as evidence of connectivity.

## 4. Establish the non-listening control (C2)

Stop only the test listener with Ctrl+C. Verify no other process is listening on
18080. Keep the firewall and network path unchanged. Make a new record/capture
set named C2 and repeat the pair with ACK first this time.

With both probe paths permitted and no listener, predict SYN `closed` and ACK
`unfiltered`. The comparison checks that ACK does not claim to identify listener
state. Keep both machines' captures and both commands' stdout/stderr.

## 5. Review before introducing drops

Qualification needs both controls to agree with verified configuration and
packet evidence. Keep failed attempts too. Two control pairs are an initial
check, not evidence of reliability or a completed experiment.

Next identify the active firewall manager and inspect rule order/connection
tracking. Then plan the isolated 18080 rules for C3–C5, with restoration steps and
management access preserved. This guide deliberately makes no firewall changes.
Follow the [full experiment plan](syn-vs-ack.md) for the 20-pair pilot, alternating
order, explicit denominators, repeated controls, and separate expected/measured
records. Never infer that ACK silence proves filtering or that a reset proves an
application connection would succeed.
