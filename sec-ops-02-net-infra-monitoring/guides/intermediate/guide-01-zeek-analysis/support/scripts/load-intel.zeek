# Zeek Script: Load Threat Intelligence and Generate Notices
# ===========================================================
# Loads threat intelligence indicators from flat files and uses
# Zeek's built-in Intel framework to match them against live traffic.
#
# The Intel framework automatically generates Intel::Notice entries
# in notice.log whenever a match is found.
#
# Usage:
#   zeek -C -r /pcap/traffic.pcap load-intel.zeek
#   grep "Intel::ADDR\|Intel::DOMAIN\|Intel::URL" notice.log

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

# Load indicator files (paths are relative to where zeek is run,
# or use absolute paths in production).
redef Intel::read_files += {
    "/intel/bad-ips.txt",
    "/intel/bad-domains.txt",
    "/intel/bad-urls.txt",
};

# Optionally: customise the notice message format.
hook Intel::policy(s: Intel::Seen, items: set[Intel::Item]) &priority=5
{
    for (item in items)
        {
        print fmt("[INTEL MATCH] type=%s  indicator=%s  source=%s  desc=%s",
                  item$ind$indicator_type, item$ind$indicator,
                  (item$meta?$source ? item$meta$source : "-"),
                  (item$meta?$desc   ? item$meta$desc   : "-"));
        }
}
