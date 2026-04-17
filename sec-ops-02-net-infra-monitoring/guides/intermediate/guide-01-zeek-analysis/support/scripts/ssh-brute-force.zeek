# Zeek Script: Detect SSH Brute Force
# =====================================
# Generates a Notice when a single source IP makes more than
# `threshold` SSH connection attempts within `time_window` seconds.
#
# Usage:
#   zeek -C -r /pcap/traffic.pcap ssh-brute-force.zeek
#   cat notice.log | zeek-cut ts note msg

module SSHBruteForce;

export {
    redef enum Notice::Type += {
        ## Fired when more than `threshold` SSH connections are seen
        ## from a single source IP within `time_window` seconds.
        SSH_Brute_Force
    };

    ## Number of SSH connections that triggers the alert.
    const threshold: count = 5 &redef;

    ## Time window over which connections are counted.
    const time_window: interval = 60sec &redef;
}

## Track connection attempts per source IP.
## The &create_expire attribute automatically clears the counter
## after `time_window` seconds of inactivity from that source.
global ssh_attempts: table[addr] of count
    &default = 0
    &create_expire = 60sec;

event connection_state_remove(c: connection)
{
    # Only process TCP connections to port 22 (SSH).
    if (c$id$resp_p != 22/tcp)
        return;

    # Increment the attempt counter for this source IP.
    ++ssh_attempts[c$id$orig_h];

    # Fire a notice if the threshold is exceeded.
    if (ssh_attempts[c$id$orig_h] >= threshold)
        {
        NOTICE([$note    = SSH_Brute_Force,
                $conn    = c,
                $msg     = fmt("SSH brute force from %s: %d attempts in 60s",
                               c$id$orig_h, ssh_attempts[c$id$orig_h]),
                $identifier    = cat(c$id$orig_h),
                $suppress_for  = 10min]);
        }
}
