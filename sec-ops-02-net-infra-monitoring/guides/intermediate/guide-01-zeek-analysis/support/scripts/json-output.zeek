# Zeek Script: Enable JSON Log Output
# =====================================
# By default Zeek writes TSV logs.  Enable JSON for SIEM integration.
# JSON logs are easier to ingest with Filebeat, Logstash, or Splunk.
#
# Usage:
#   zeek -C -r /pcap/traffic.pcap json-output.zeek
#   cat conn.log | jq '.id'

redef LogAscii::use_json = T;

# Optional: add a @timestamp field for Elastic compatibility
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
