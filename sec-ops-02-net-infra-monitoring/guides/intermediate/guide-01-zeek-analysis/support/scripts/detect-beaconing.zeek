# Zeek Script: Detect Command-and-Control Beaconing
# ====================================================
# Detects hosts that connect to the same external destination repeatedly
# at very regular intervals (±5 seconds) with similar payload sizes.
# This pattern is characteristic of malware "check-in" or heartbeat traffic.
#
# Usage:
#   zeek -C -r /pcap/traffic.pcap detect-beaconing.zeek
#   cat notice.log | zeek-cut ts note msg

module BeaconingDetection;

export {
    redef enum Notice::Type += {
        ## Fired when a host exhibits regular, periodic connection behaviour
        ## consistent with C2 beaconing.
        Possible_C2_Beaconing
    };

    ## Minimum number of connections required to declare beaconing.
    const min_connections: count = 5 &redef;

    ## Maximum allowed standard deviation in connection intervals (seconds).
    ## Lower = stricter (requires more regular timing).
    const max_interval_stdev: double = 10.0 &redef;

    ## Maximum allowed variance in bytes per connection (as fraction of mean).
    ## 0.20 = allow ±20% variance.
    const max_byte_variance_ratio: double = 0.20 &redef;
}

## Store connection timestamps and byte counts per (src, dst, dport) tuple.
type FlowRecord: record {
    timestamps: vector of double;
    byte_counts: vector of count;
};

global flow_history: table[string] of FlowRecord
    &create_expire = 2hr;

## -----------------------------------------------------------------------
## Helper: compute mean and standard deviation from a vector of doubles
## -----------------------------------------------------------------------
function mean_stdev(values: vector of double): vector of double
{
    local n = |values|;
    if (n < 2)
        return vector(0.0, 0.0);

    local sum = 0.0;
    for (i in values)
        sum += values[i];
    local mean = sum / n;

    local variance = 0.0;
    for (i in values)
        {
        local diff = values[i] - mean;
        variance += diff * diff;
        }
    variance = variance / (n - 1);

    return vector(mean, sqrt(variance));
}

## -----------------------------------------------------------------------
## Record each completed connection for beaconing analysis
## -----------------------------------------------------------------------
event connection_state_remove(c: connection)
{
    # Only analyse established TCP/UDP connections with known byte counts.
    if (c$conn_state != "SF")
        return;

    # Skip connections to internal/RFC1918 space (we only care about C2 to internet).
    local dst = c$id$resp_h;
    if (/^10\./ == cat(dst) || /^192\.168\./ == cat(dst) || /^172\.(1[6-9]|2[0-9]|3[0-1])\./ == cat(dst))
        return;

    local key = fmt("%s-%s-%d", c$id$orig_h, c$id$resp_h, c$id$resp_p);

    if (key !in flow_history)
        {
        flow_history[key] = FlowRecord(
            $timestamps  = vector(),
            $byte_counts = vector()
        );
        }

    flow_history[key]$timestamps  += network_time() + 0.0;
    flow_history[key]$byte_counts += c$orig$size;

    local n_conns = |flow_history[key]$timestamps|;

    # Only check after we have enough data points.
    if (n_conns < min_connections)
        return;

    # Calculate intervals between consecutive connections.
    local intervals: vector of double = vector();
    local ts = flow_history[key]$timestamps;
    for (i in ts)
        {
        if (i == 0) next;
        intervals += ts[i] - ts[i - 1];
        }

    local stats = mean_stdev(intervals);
    local interval_mean = stats[0];
    local interval_stdev = stats[1];

    # Check byte count variance.
    local bytes = flow_history[key]$byte_counts;
    local total_bytes = 0.0;
    for (i in bytes)
        total_bytes += bytes[i] + 0.0;
    local bytes_mean = total_bytes / |bytes|;

    local max_b = bytes[0] + 0.0;
    local min_b = bytes[0] + 0.0;
    for (i in bytes)
        {
        if (bytes[i] + 0.0 > max_b) max_b = bytes[i] + 0.0;
        if (bytes[i] + 0.0 < min_b) min_b = bytes[i] + 0.0;
        }

    local byte_variance_ratio = (bytes_mean > 0.0) ? (max_b - min_b) / bytes_mean : 1.0;

    # Fire notice if both timing and size are regular.
    if (interval_stdev <= max_interval_stdev &&
        byte_variance_ratio <= max_byte_variance_ratio)
        {
        NOTICE([$note       = Possible_C2_Beaconing,
                $src        = c$id$orig_h,
                $dst        = c$id$resp_h,
                $msg        = fmt("Beaconing detected: %s -> %s:%d  connections=%d  "
                                  "interval=%.1fs (stdev=%.1f)  bytes/conn=%.0f (variance=%.0f%%)",
                                  c$id$orig_h, c$id$resp_h, c$id$resp_p, n_conns,
                                  interval_mean, interval_stdev,
                                  bytes_mean, byte_variance_ratio * 100),
                $identifier     = key,
                $suppress_for   = 1hr]);
        }
}
