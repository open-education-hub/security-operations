# Zeek Script: Detect Potential DGA (Domain Generation Algorithm) Domains
# =========================================================================
# Flags DNS queries where the leftmost label (subdomain) is unusually long
# or has a high ratio of consonants-to-vowels, which is characteristic of
# algorithmically generated domain names.
#
# Usage:
#   zeek -C -r /pcap/traffic.pcap dga-detection.zeek
#   cat notice.log | zeek-cut ts note msg

module DGADetection;

export {
    redef enum Notice::Type += {
        ## Fired when a DNS query has an unusually long or random-looking subdomain.
        Possible_DGA_Domain
    };

    ## Minimum subdomain label length to consider suspicious.
    const min_label_length: count = 18 &redef;

    ## Minimum number of distinct NXDOMAIN responses per source within
    ## the observation window before an alert fires.
    const nxdomain_threshold: count = 10 &redef;

    ## Observation window for NXDOMAIN counting.
    const nxdomain_window: interval = 5min &redef;
}

## Count NXDOMAIN responses per source IP.
global nxdomain_counts: table[addr] of count
    &default = 0
    &create_expire = 5min;

## -----------------------------------------------------------------------
## Helper: compute approximate entropy of a string (higher = more random)
## -----------------------------------------------------------------------
function char_entropy(s: string): double
{
    local freq: table[string] of count &default = 0;
    local len = |s|;
    if (len == 0)
        return 0.0;

    for (i in s)
        ++freq[s[i]];

    local entropy = 0.0;
    for (ch in freq)
        {
        local p = freq[ch] + 0.0;
        p = p / len;
        if (p > 0.0)
            entropy -= p * log(p) / log(2.0);
        }
    return entropy;
}

## -----------------------------------------------------------------------
## Check each DNS request for suspicious subdomain length
## -----------------------------------------------------------------------
event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
{
    if (|query| == 0)
        return;

    # Split on '.' and examine the leftmost label.
    local labels = split_string(query, /\./);
    if (|labels| == 0)
        return;

    local subdomain = labels[0];

    # Alert if the leftmost label exceeds the length threshold.
    if (|subdomain| >= min_label_length)
        {
        NOTICE([$note         = Possible_DGA_Domain,
                $conn         = c,
                $msg          = fmt("Long DNS subdomain query from %s: %s (%d chars in label '%s')",
                                    c$id$orig_h, query, |subdomain|, subdomain),
                $identifier   = query,
                $suppress_for = 1hr]);
        }
}

## -----------------------------------------------------------------------
## Count NXDOMAIN responses per source; alert on high rate
## -----------------------------------------------------------------------
event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
{
    # Only look at responses (not queries).
    if (is_orig)
        return;

    # rcode 3 = NXDOMAIN.
    if (msg$rcode != 3)
        return;

    ++nxdomain_counts[c$id$orig_h];

    if (nxdomain_counts[c$id$orig_h] >= nxdomain_threshold)
        {
        NOTICE([$note         = Possible_DGA_Domain,
                $conn         = c,
                $msg          = fmt("High NXDOMAIN rate from %s: %d NXDOMAINs in 5 minutes",
                                    c$id$orig_h, nxdomain_counts[c$id$orig_h]),
                $identifier   = cat(c$id$orig_h),
                $suppress_for = 30min]);
        }
}
