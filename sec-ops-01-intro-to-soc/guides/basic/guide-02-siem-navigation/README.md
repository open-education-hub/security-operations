# Guide 02 (Basic): Navigating the SIEM Interface

## Objective

Learn to navigate Splunk's interface, understand the main components, and run your first security-relevant queries.

## Prerequisites

* Completed Guide 01 (Splunk running at http://localhost:8000).

## Steps

### Step 1: Understanding the Splunk Navigation

When you log into Splunk, you'll see the following main sections:

* **Home**: Overview and recently accessed items.
* **Search & Reporting** (App): Where you write and run searches.
* **Dashboards**: Pre-built and custom visual displays.
* **Settings**: System configuration (data inputs, users, indexes).
* **Apps**: Additional Splunk applications.

### Step 2: Exploring Indexes

Splunk stores data in **indexes**.
Think of an index like a database table.

Navigate to **Settings → Indexes** to see available indexes.

In a fresh Splunk installation, you'll see:

* `_internal`: Splunk's own operational logs.
* `_audit`: Splunk audit trail.
* `main`: Default index for ingested data.

Run this query to see data in the internal index:

```spl
index=_internal | head 10
```

### Step 3: Understanding SPL (Splunk Processing Language)

SPL is how you query data in Splunk.
Basic structure:

```spl
index=<name> [filters]
| command1 [options]
| command2 [options]
```

**Most useful commands:**
| Command | Purpose | Example |
|---------|---------|---------|
| `search` | Filter events | `search "Failed password"` |
| `stats` | Aggregate data | `stats count by src_ip` |
| `timechart` | Time-series chart | `timechart count span=1h` |
| `top` | Top values | `top 10 user` |
| `rex` | Extract fields with regex | `rex "from (?<ip>\d+\.\d+\.\d+\.\d+)"` |
| `table` | Show specific fields | `table _time, user, src_ip` |
| `where` | Filter after aggregation | `where count > 10` |
| `sort` | Sort results | `sort -count` |
| `head` / `tail` | Limit results | `head 20` |

### Step 4: Ingest Sample Log Data

Download and copy the sample logs:

```bash
# Create a sample auth log
cat > /tmp/sample_auth.log << 'EOF'
Jan 15 08:23:11 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:12 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:13 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:14 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:15 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:16 server sshd[1234]: Accepted password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:30:00 server sshd[1235]: Accepted password for jdoe from 192.168.1.50 port 22 ssh2
Jan 15 09:00:00 server sshd[1236]: Failed password for root from 10.0.0.55 port 22 ssh2
Jan 15 09:00:01 server sshd[1236]: Failed password for root from 10.0.0.55 port 22 ssh2
Jan 15 09:00:02 server sshd[1236]: Failed password for root from 10.0.0.55 port 22 ssh2
EOF

# Copy into container
docker cp /tmp/sample_auth.log my-splunk:/tmp/sample_auth.log
```

In Splunk's web UI:

1. Go to **Settings → Add Data**.
1. Click **Upload**.
1. Choose the file `/tmp/sample_auth.log` (click "Select File" and navigate to it).
1. Set **Source Type** to `linux_secure`.
1. Set **Index** to `main`.
1. Click through and **Submit**.

### Step 5: Run Your First Security Queries

**Query 1: Find all failed logins**

```spl
index=main sourcetype=linux_secure "Failed password"
```

**Query 2: Count failures by user**

```spl
index=main sourcetype=linux_secure "Failed password"
| stats count by user
| sort -count
```

**Query 3: Find all logins (success and failure)**

```spl
index=main sourcetype=linux_secure
| rex "(?<status>Failed|Accepted) password for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, status, user, src_ip
```

### Step 6: Save a Search

1. Run Query 3 from Step 5.
1. Click **Save As → Report**.
1. Name it: `Login Activity Overview`.
1. Click **Save**.
1. Click **View** to see the saved report.

### Step 7: Change Time Range

Splunk searches default to **Last 24 hours**.
To change:

* Click the time picker (top right of search bar).
* Choose: All Time, Last 7 days, or a custom range.

For your sample data, choose **All Time** to ensure all events appear.

## Verification

* [ ] You can navigate to Search & Reporting.
* [ ] The sample log data is ingested and searchable.
* [ ] Query 3 returns results with status, user, and IP columns.
* [ ] You have saved a report.

## Summary

You can now navigate Splunk, understand the index system, write basic SPL queries, and save searches as reports.
These skills form the foundation of SIEM-based security analysis.
In the next guide, you'll build on this to create an alert workflow.
