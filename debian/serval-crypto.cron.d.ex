#
# Regular cron jobs for the serval-crypto package
#
0 4	* * *	root	[ -x /usr/bin/serval-crypto_maintenance ] && /usr/bin/serval-crypto_maintenance
