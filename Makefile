all:
	(cd logaudit && go build)
	(cd logauditd && go build)
	(cd logauditsubmit && go build)
	(cd logtopatterns && go build)
