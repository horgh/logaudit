# logaudit
This program is to make examining log files on GNU/Linux machines simpler
(Debian/Ubuntu with syslog, specifically).

I have a few machines and I want to keep an eye on the logs. One problem is
that there are many log messages I don't really care about. Another is that it
is time consuming to go and look at each log file on each host.

This program examines all log files in /var/log. It outputs all of the log
lines at once. You can configure it to ignore certain files all together, or to
ignore lines with regexes.

I hope this to make monitoring the logs more efficient for me.

I know there are other solutions out there to do things like this (such as
logwatch). However I want fine grained control and to know deeply about what
logs I watch and what messages I see or do not see.
