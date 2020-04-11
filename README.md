# logaudit

logaudit is a tool for gathering and analyzing log files. I intend it for
logs such as those in GNU/Linux systems under `/var/log`.

I have a few machines and I want to keep an eye on the logs. One problem is
that there are many log messages I don't care about. Another is that it is
time consuming to look at logs on each host.

I hope this to make monitoring the logs more efficient for me.


# How it works

logaudit runs on each host where you want to monitor logs. Typically it
runs from cron. It reads logs from `/var/log`, filters them, and publishes
lines of interest to a GCP Pub/Sub topic. I use
[emailpub](https://github.com/horgh/emailpub) to email me this summary.


# Setup

Create a service account and allow it to publish to GCP Pub/Sub. If
necessary, copy the key to the host.

Create a config and copy it to the host.

Add logaudit to root's cron:

```
21 6 * * * GOOGLE_APPLICATION_CREDENTIALS=service-account.json /path/to/logaudit \
  -config /path/to/logaudit.conf \
  -email you@example.com  \
  -project-id myproject \
  -state-file /path/to/logaudit.state \
  -topic mytopic 2>&1 | logger
```

Note `GOOGLE_APPLICATION_CREDENTIALS` only needs to be set if you're using
a key from a file.
