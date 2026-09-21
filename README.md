# ms-msmq-queuejumper

An Nmap NSE script that checks Microsoft Message Queuing (MSMQ) for **CVE-2023-21554**, aka **"QueueJumper"**, an unauthenticated remote code execution vulnerability in the MSMQ service on TCP port **1801** (CVSS 9.8).

The script performs a **crash-safe** differential check. It does not send an out-of-bounds write payload. It only distinguishes patched from unpatched hosts by whether the service replies to a malformed probe.

## How it works

The check reproduces the two-stage logic of the Metasploit module `auxiliary/scanner/msmq/cve_2023_21554_queuejumper`:

1. **Stage 1 — confirm MSMQ.** Send a well-formed MSMQ SRMP message. Any live MSMQ instance, patched or not, replies with a packet containing the static 4-byte signature `LIOR` (`0x4C494F52`). This confirms the service is MSMQ.
2. **Stage 2 — trigger the overflow.** Resend the message with the `SRMPEnvelopeHeader` `DataLength` field increased by `0x80000000`, causing an integer overflow in the size check.
   - **Vulnerable** hosts still reply; the response contains `LIOR`.
   - **Patched** hosts detect the overflow, raise an exception, and send **no response**.

The two probes embedded in the script are byte-for-byte identical except for the four `DataLength` bytes at offset 232. They were generated from the Metasploit module's own packet construction and verified (the `LIOR` signature at offset 4, the `packet_size` field equal to the 2380-byte packet length, and the single-byte delta at the overflow field).

## Requirements

- Nmap with NSE support (any modern version).
- Network reachability to TCP/1801 on the target.

## Usage

```bash
nmap -Pn -p1801 --script ms-msmq-queuejumper <target>

# longer response wait (default is 5000 ms)
nmap -Pn -p1801 --script ms-msmq-queuejumper --script-args queuejumper.timeout=8000 <target>
```

Run the script from this directory with `--script ./ms-msmq-queuejumper.nse`, or copy it into your Nmap scripts directory (for example `/usr/share/nmap/scripts/`) and run `sudo nmap --script-updatedb` first.

### Arguments

| Argument | Default | Description |
|---|---|---|
| `queuejumper.timeout` | `5000` | Milliseconds to wait for each stage's response. |

## Output

The script reports one of the following states:

| State | Meaning |
|---|---|
| `VULNERABLE` | MSMQ present and it replied to the stage-2 overflow probe. Missing the April 2023 patch. |
| `NOT VULNERABLE` | MSMQ present but silent on stage 2. Consistent with a patched host. |
| `LIKELY VULNERABLE (manual review)` | MSMQ present but stage 2 returned an unexpected, non-`LIOR` response. Verify manually. |
| `NOT MSMQ` | Port answered but returned no `LIOR` signature. Service is not MSMQ. |
| `INCONCLUSIVE` | The probe could not be completed (connect, send, or timeout issue). |

Example:

```
PORT     STATE SERVICE
1801/tcp open  msmq
| ms-msmq-queuejumper:
|   cve: CVE-2023-21554 (QueueJumper) MSMQ RCE
|   state: VULNERABLE
|   evidence: MSMQ replied to the malformed SRMP (DataLength overflow) probe; overflow was not rejected.
|   cvss: 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
|_  note: Missing the April 2023 patch for CVE-2023-21554.
```

## Limitations

- The `portrule` fires only when TCP/1801 is **open**. A host whose 1801 is filtered or closed cannot be assessed remotely by this or any other network probe.
- A remote-only check confirms exploitability but does not, by itself, prove a patch is absent when the service does not answer. For hosts that are unreachable on 1801, corroborate with a **credentialed** check (missing April 2023 update, or MSMQ binary version) to establish patch state authoritatively.

## Legal / authorized use

Use this script only against systems you own or are explicitly authorized to test, such as under a signed statement of work. Unauthorized scanning may be illegal.

## Credits

- Vulnerability discovery: **Wayne Low** and **Haifei Li**.
- Original Metasploit detection module: **Bastian Kanbach** (`@__bka__`). The probe packet layout used here is ported from that module.

## References

- Microsoft advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554
- IBM X-Force technical analysis: https://www.ibm.com/think/x-force/msmq-queuejumper-rce-vulnerability-technical-analysis
- Metasploit module: https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/msmq/cve_2023_21554_queuejumper.rb

## License

Same as Nmap. See https://nmap.org/book/man-legal.html
