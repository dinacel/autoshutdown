#!/bin/sh

# Basic install script for autoshutdown on Debian/Ubuntu/OMV-Systems
# Solo0815 - R. Lindlein - walterheisenberg (at) gmx (dot) com

f_checksuccess(){
	if [ "$?" = 0 ]; then 
		echo "$1 successfull!"
		echo
	else
		echo "$1 not successfull"
		echo "Stopping script!"
		echo
		exit 1
	fi
}

echo "autoshutdown-install-script"
echo

#cp autoshutdown.conf /etc/ 
#f_checksuccess "autoshutdown.conf"

cp autoshutdown.default /etc/ 
f_checksuccess "autoshutdown.default"

if [ ! -f /etc/autoshutdown.conf ]; then
	cp autoshutdown.default /etc/autoshutdown.conf
	f_checksuccess "creating autoshutdown.conf"
else
	echo "autoshutdown.conf found - don't create one"
fi

cp autoshutdownlog.conf /etc/rsyslog.d/ 
f_checksuccess "autoshutdownlog.conf"

cp autoshutdown.sh /usr/local/bin/
f_checksuccess "move autoshutdown.sh"

if [ ! -x /usr/local/bin/autoshutdown.sh ]; then
	echo "Make autoshutdown.sh executable"
	chmod +x /usr/local/bin/autoshutdown.sh
	f_checksuccess "make autoshutdown.sh executable"
fi

if ! which fping > /dev/null; then
	echo -n "fping is not installed. Should it be installed for you? (y/n)"
	read answer -n 1 
	case $answer in
		y|Y)
			apt-get install -y fping
			;;
		*)
			echo
			echo "fping will not be installed. The script will not work."
			echo "Install it manually with 'apt-get install fping'"
			;;
	esac
else
	echo
	echo "fping is installed"
fi

cp autoshutdown /etc/init.d/
f_checksuccess "move autoshutdown"

echo 
echo -n "Should 'autoshutdown' run at startup via /etc/init.d? (Y/n) "
read otheranswer -n 1 
	case $otheranswer in
		y|Y)
			update-rc.d autoshutdown defaults
			;;
		*)
			echo "autoshutdown will not run at startup. Maybe your PC will not shutdown"
			;;
		esac

echo
echo "Starting autoshutdown-script ..."
/etc/init.d/autoshutdown start

exit 0
