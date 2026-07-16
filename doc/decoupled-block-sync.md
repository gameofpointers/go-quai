# Decoupled historical block sync

Historical sync has two independent progress points:

- **downloaded head**: the highest contiguous Prime block whose full body is durably stored;
- **processed head**: the canonical block whose state and hierarchical ETX effects have been applied.

The Prime downloader requests canonical ranges and immediately expands their manifests into Region requests. Region downloads immediately expand their manifests into Zone requests. These operations do not wait for a dominant append attempt.

## P2P requests

Bulk sync extends the existing `work_object_blocks` request with optional fields:

- `max_blocks` limits object count;
- `max_bytes` limits encoded payload size;
- `hashes` requests manifest blocks directly;
- the existing `number` field remains the origin for a canonical range.

The defaults are 128 blocks and 2 MiB per request. Responses remain below the 3 MiB stream-message limit. Only one peer owns a bulk range at a time; a failed request is retried against another eligible peer. Single-object requests remain as a rolling-upgrade fallback.

Older peers ignore the optional protobuf fields and treat a range as the legacy ten-block request. Hash batches returned with legacy contiguous semantics fail strict client validation and fall back to individual hash requests.

## Storage and restart behavior

Downloaded work objects are structurally validated and written in a database batch together with an `awaiting import` marker. The downloader does not write canonical hashes, receipts, state, or transaction indexes.

The append worker loads at most 100,000 durable markers into memory. Additional downloaded blocks remain on disk. When the working set drains, it is refilled in block-number order. Successful import deletes the marker. On restart, the working set and subordinate manifest work are reconstructed from these markers.

The body bytes use the normal work-object store, so historical sync does not require a second copy of the blockchain.

## Fork handling

Every range is checked for contiguous heights and parent hashes. The first block must also extend the durable downloaded head. If the peer's canonical chain no longer extends an unprocessed downloaded tip, sync rewinds one downloaded checkpoint and retries. This path never rewinds processed canonical state.

## Metrics

`HistoricalSync` counter labels are emitted per location for:

- `requests`
- `blocks`
- `bytes`
- `failures`

`HistoricalSyncHead` gauge labels expose downloaded and processed heights. The periodic core status log also reports both heights and their headroom.

For 150 GB in five hours, useful payload throughput must average at least 8.3 MB/s. Operationally, target 12–15 MB/s to cover protobuf framing, retries, and peer variance.
