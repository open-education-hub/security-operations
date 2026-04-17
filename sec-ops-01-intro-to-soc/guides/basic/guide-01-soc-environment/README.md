# Guide 01 (Basic): Setting Up Your SOC Lab Environment

## Objective

Set up a basic security operations lab environment using Docker.
By the end of this guide, you will have a running Splunk instance ready to receive and analyze security logs.

## Prerequisites

* Docker Desktop (Windows/macOS) or Docker Engine (Linux) installed and running.
* At least 4 GB of free RAM and 10 GB of free disk space.
* Basic familiarity with the command line.

## Resources

* Docker: https://docs.docker.com/get-docker/
* Splunk Docker image: https://hub.docker.com/r/splunk/splunk

## Steps

### Step 1: Verify Docker is Running

Open a terminal and run:

```console
docker --version
docker ps
```

You should see a Docker version number and an empty container list (or existing containers).

### Step 2: Pull the Splunk Docker Image

```console
docker pull splunk/splunk:latest
```

This may take several minutes depending on your connection speed.
The image is approximately 1.5 GB.

### Step 3: Start the Splunk Container

```console
docker run -d \
  --name my-splunk \
  -p 8000:8000 \
  -p 9997:9997 \
  -e SPLUNK_GENERAL_TERMS='--accept-sgt-current-at-splunk-com' \
  -e SPLUNK_START_ARGS='--accept-license' \
  -e SPLUNK_PASSWORD='D4Sec-sec-ops!' \
  splunk/splunk:latest
```

Parameter explanation:

* `-d`: Run in detached (background) mode.
* `--name my-splunk`: Give the container a friendly name.
* `-p 8000:8000`: Expose Splunk's web interface.
* `-p 9997:9997`: Expose Splunk's log receiver port.
* `SPLUNK_PASSWORD`: Sets the admin password.

### Step 4: Wait for Splunk to Initialize

Splunk takes 2-3 minutes to start.
Monitor its progress:

```console
docker logs -f my-splunk
```

When you see `Splunk is now ready`, press `Ctrl+C` to stop following the logs.

### Step 5: Access Splunk

Open your browser and go to:

```text
http://localhost:8000
```

Log in with:

* Username: `admin`
* Password: `SOClab2024!`

You should see the Splunk home screen.

### Step 6: Navigate to Search & Reporting

1. Click **Apps** in the top menu.
1. Click **Search & Reporting**.
1. In the search bar, type:

   ```spl
   index=_internal | head 5
   ```

1. Click the green **Search** button (or press Enter).

You should see Splunk's internal log entries.
Congratulations — your SIEM is working!

### Step 7: Stop and Start the Container

To stop Splunk (preserving data):

```console
docker stop my-splunk
```

To start it again:

```console
docker start my-splunk
```

To remove the container completely:

```console
docker stop my-splunk && docker rm my-splunk
```

## Verification

Your lab environment is working correctly if:

* [ ] `docker ps` shows `my-splunk` container running.
* [ ] You can access `http://localhost:8000` in a browser.
* [ ] You can log in with admin/SOClab2024!
* [ ] A basic SPL query in Search & Reporting returns results.

## Summary

You have successfully set up a Splunk SIEM instance in Docker.
This environment will be used throughout the Security Operations course for log analysis, alert creation, and incident investigation.
Having a local, isolated SIEM environment allows you to experiment freely without affecting production systems.

In a real SOC, Splunk would be connected to dozens or hundreds of data sources — from firewalls and endpoints to cloud services and applications — providing a complete picture of the organization's security posture.
