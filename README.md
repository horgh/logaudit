# Summary
This is a set of programs to gather and analyze log files. I intend it for logs
such as those in GNU/Linux systems under /var/log.

I have a few machines and I want to keep an eye on the logs. One problem is
that there are many log messages I don't really care about. Another is that it
is time consuming to go and look at each log file on each host.

I hope this to make monitoring the logs more efficient for me.

I know there are other solutions out there to do things like this (such as
logwatch, logstash, fluentd). However I want fine grained control and to know
deeply about what logs I watch and what messages I see or do not see.


# How it works

  * Collection: logauditsubmit runs on a single host. Typically it will run
    regularly from cron. It reads all logs from /var/log and then sends them via
    an HTTP request to logauditd.
  * Storage: logauditd accepts logs from logauditsubmit clients and stores them
    in a database. Right now it can store logs into a PostgreSQL database.
  * Analysis: logaudit retrieves logs from the database and applies filters to
    determine whether to show each line.
