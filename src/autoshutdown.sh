#!/bin/bash

#=======================================================================
#
#          FILE:	autoshutdown.sh
#
#         USAGE:	copy this script and libs.sh to /usr/local/bin and teh config-file to /etc
#
#   DESCRIPTION:	shuts down a PC/Server - variable options
#
#  REQUIREMENTS:  	Debian / Ubuntu-based system
#          BUGS:  	---
#        AUTHOR:	Solo0815 - R. Lindlein (Ubuntu-Port, OMV-Changes), it should work on any Debain-based System, too
#					based on autoshutdown.sh v0.7.008 by chrikai, see: https://sourceforge.net/apps/phpbb/freenas/viewtopic.php?f=12&t=2158&start=60
#=======================================================================

# 2010/Dec/27		0.1.00 	: Ubuntu-Port:
#							: and separating cfg in /etc/autoshutdown.conf
# 2011/Jan/04		0.1.01	: separating _log in libs.sh
# 2011/Jan/15		0.1.02	: bugfix for "top: failed to get tty" - use -b switch in top
#				 			: other bugfixes
# 2012/Mar/12		0.1.03	: imprve: added clockcheck function to force going to sleep on given hour (lucafa) 
#                     		: bugfix: removed issue with command line -> -a -b -c -d -h -v -V is now accepted as well as -abcdhvV      
#							: thx Chirikai! See above Link to FreeNAS-Forum
#							: OMV-Port
#							: improved ping-function with fping. Should be faster now
# 2012/Mar/16		0.1.04	: some Code-cleanup
# 2012/Mar/17		0.1.05	: remove Background-Scan, because fping is so fast, we don't need it
#							: remove bootup-phase
#							: Code cleanup
# 2012/Mar/20		0.1.06	: added config-Check and default variables
#							: removed Command-Line options and help -> we have a config
#							: removed libs.sh - who wants to use it > /usr/local/bin/libs.sh
# 2012/Mar/21		0.1.07	: fixed the REGEX-Error at systemstart - it works from CLI, but not @ systemstart :o
#							: autoread IP from ifconfig (only eth0 at the moment)
#							: minor changes 
# 							: more config-checks
# 2012/Mar/22		0.1.08	: expert-setting: SHUTDOWNCOMMAND (see autoshutdown.conf)
#							: expert-setting: PINGLIST (see autoshutdown.conf)
#							: Log-Entry in /var/log/syslog when shutdown is initiated
#							: autodetect NICs and check all of them


######## VARIABLE DEFINITION ########
RESULT=0               # declare reusable RESULT variable to check function return values
ACTIVEIPS=""            # declare empty list of active IPs

# Variables that normal users should normaly not define - PowerUsers can do it here or add it to the config
LPREPEAT=10         	# number of test cycles for finding and active L-Process (default=10)
TPREPEAT=5            	# number of test cycles for finding and active T-Process (default=5)

LOGGER="/usr/bin/logger"  	 # path and name of logger (default="/usr/bin/logger")
FACILITY="local6"         	# facility to log to -> see syslog.conf  
							# for a separate Log, add the line (default="local6")
							# "local6.* %/var/log/autoshutdown.log" to syslog.conf
							# then you have a separate log with all autoshutdown-entrys

######## CONSTANT DEFINITION ########
VERSION="0.1.08"         # script version information
CTOPPARAM="-d 1 -n 1"         # define common parameters for the top command line (default="-d 1") - for Debian/Ubuntu: "-d 1 -n 1"
STOPPARAM="-i $CTOPPARAM"   # add specific parameters for the top command line  (default="-I $CTOPPARAM") - for Debian/Ubuntu: "-i $CTOPPARAM"

######## FUNCTION DECLARATION ########

################################################################
#
#   name      : _log
#   parameter   : $LOGMESSAGE : logmessage in format "PRIORITY: MESSAGE"
#   return      : none
#
_log()
{(
	[[ "$*" =~ ^([A-Za-z]*):(.*) ]] &&
		{
			PRIORITY=${BASH_REMATCH[1]}
			LOGMESSAGE=${BASH_REMATCH[2]}
			[[ "$(basename "$0")" =~ ^(.*)\. ]] && LOGMESSAGE="${BASH_REMATCH[1]}[$$]: $PRIORITY: '$LOGMESSAGE'";
		}

	if $VERBOSE ; then
		# next line only with implementation where logger does not support option '-s'
		# echo "$(date '+%b %e %H:%M:%S'):$LOGMESSAGE"

		[ $SYSLOG ] && $LOGGER -s -t "$(date '+%b %e %H:%M:%S'): $USER" -p $FACILITY.$PRIORITY "$LOGMESSAGE"

	else
		[ $SYSLOG ] && $LOGGER -p $FACILITY.$PRIORITY "$LOGMESSAGE"

	fi   # > if [ "$VERBOSE" = "NO" ]; then

)}

################################################################
#
#   name         : _ping_range
#   parameter      : none
#   global return   : ACTIVEIPS : list of all active hosts in given IP range, separated by blank
#   return value   : CNT       : number of active IP hosts within given IP range

_ping_range()
{
	NWADAPTERNR_PINGRANGE="$1"
	PINGRANGECNT=0
	ACTIVEIPS=""
	#IPING=
	CREATEPINGLIST="false"
		
	# Create only one pinglist at script-start and not every function-call
	# If pinglist exists, don't create it
	if [ -z $USEOWNPINGLIST ]; then
		PINGLIST="/tmp/pinglist"
		if [ ! -f "$PINGLIST" ]; then
			CREATEPINGLIST="true"
		fi
	fi

	if $DEBUG; then 
		_log "DEBUG: NWADAPTERNR_PINGRANGE: $NWADAPTERNR_PINGRANGE"
		_log "DEBUG: PINGLIST: $PINGLIST"
		_log "DEBUG: _ping_range(): RANGE: '$RANGE'"
		_log "DEBUG: _ping_range(): CLASS: '${CLASS[${NWADAPTERNR_PINGRANGE}]}'"
	fi
	# separate the IP end number from the loop counter, to give the user a chance to configure the search "algorithm"
	# COUNTUP = 1 means starting at the lowest IP address; COUNTUP=0 will start at the upper end of the given range
	for RG in ${RANGE//,/ } ; do

		if [[ ! "$RG" =~ \.{2} ]]; then

			FINIT="J=$RG"
			FORCHECK="J<=$RG"
			STEP="J++"

		elif [[ "$RG" =~ ^([0-9]{1,3})\.{2}([0-9]{1,3}$) ]]; then

			if [ ${BASH_REMATCH[2]} -gt ${BASH_REMATCH[1]} ]; then
				FINIT="J=${BASH_REMATCH[1]}"
				FORCHECK="J<=${BASH_REMATCH[2]}"
				STEP="J++"
			else
				FINIT="J=${BASH_REMATCH[1]}"
				FORCHECK="J>=${BASH_REMATCH[2]}"
				STEP="J--";
			fi   # > if [ ${BASH_REMATCH[2]} -gt ${BASH_REMATCH[1]} ]; then

		fi   # > if [[ "$RG" =~ [0-9]{1,3} ]]; then

		for (( $FINIT;$FORCHECK;$STEP )); do

			# If the pinglist is not created, create it with all IPs
			# don't add the ServerIP (OMV-IP) to the pinglist.
			# TODO: specify pinglist-file in autoshutdown.conf
			
			if $CREATEPINGLIST; then echo "${CLASS[$NWADAPTERNR_PINGRANGE]}.$J" | grep -v ${CLASS[$NWADAPTERNR_PINGRANGE]}.${SERVERIP[$NWADAPTERNR_PINGRANGE]} >> $PINGLIST; fi

		done   # > for (( J=$iSTART;$FORCHECK;$STEP )); do

	done   # > for RG in ${RANGE//,/ } ; do

	_log "INFO: retrieve list of active IPs for '${NWADAPTER[$NWADAPTERNR_PINGRANGE]}' ..."

	# fping output 2> /dev/null suppresses the " ICMP Host Unreachable from 192.168.178.xy for ICMP Echo sent to 192.168.178.yz"
	if [ -f $PINGLIST ]; then
		FPINGRESULT="$(fping -a -r1 < "$PINGLIST" 2>/dev/null)"
	else
		_log "INFO: PINGLIST: $PINGLIST does not exist. Skip fpinging hosts"
	fi
	for ACTIVEPC in $FPINGRESULT; do
		_log "INFO: Found IP $ACTIVEPC as active host."
		let PINGRANGECNT++;
	done
	ACTIVEIPS="$FPINGRESULT"
	
	if [ -z "$FPINGRESULT" ]; then
		_log "INFO: No active IPs in the specified IP-Range found"
	fi

   return ${PINGRANGECNT};
}

################################################################
#
#   name      : _shutdown
#   parameter   : none
#   return      : none, script exit point
#
_shutdown()
{
   # Goodbye and thanks for all the fish!!
   # We've had no responses for the required number of consecutive scans
   # defined in FLAG shutdown & power off.

	if [ "$AUTOUNRARCHECK" = "true" ]; then
		# kill the autounrar-script
		kill -9 $(ps -aef | egrep -v "(sudo|grep)" | grep auto-unrar-1.1.2 | awk '{print $2}')
		if [ $? -ne 0 ]; then
			_log "WARN: Error occured: kill $(ps -ef | egrep -v '(sudo|grep)' | grep auto-unrar-1.1.2 | awk '{print $2}')"
		else
			_log "INFO: Java sucessfull killed (autounrar)"
		fi
	fi

	if [ -z "$SHUTDOWNCOMMAND" ]; then
		SHUTDOWNCOMMAND="shutdown -h now"
	fi

	logger -s -t "$(date '+%b%e - %H:%M:%S'): $USER - : $(basename "$0" | sed 's/\.sh$//g')[$$]" "INFO: Shutdown issued: '$SHUTDOWNCOMMAND'"
	_log "INFO: Shutdown issued: '$SHUTDOWNCOMMAND'"
	_log "   "
	_log "   "

	# write everything to disk/stick and shutdown, hibernate, $whatever is configured
	if sync; then eval "$SHUTDOWNCOMMAND"; fi
	exit 0
	}

################################################################
#
#   name      : _ident_num_proc
#   parameter   : $1...$(n-1)    : parameter for command 'top'
#            : $n         : search pattern for command 'grep'
#   return      : none
#
_ident_num_proc()
{
	# retrieve all function parameters for the top command; as we know the last command line parameter
	# is the pattern for the grep command, we can stop one parameter before the end
	[[ "$*" =~ (.*)\ (.*)$ ]] &&
		{
			TPPARAM=${BASH_REMATCH[1]}
			GRPPATTERN=${BASH_REMATCH[2]};
		}
	if $DEBUG ; then _log "DEBUG: _ident_num_proc(): top cmd line: $TPPARAM, grep cmd line: $GRPPATTERN"; fi

	# call top once, pipe the result to grep and count the number of patterns found
	# the number of found processes is returned to the callee
	NUMOFPROCESSES=$(top ${TPPARAM} | grep -c ${GRPPATTERN})

	return $NUMOFPROCESSES
}

################################################################
#
#   name         : _check_processes
#   parameter      : none
#   global return   : none
#   return         : 1      : if no active process has been found
#               : 0      : if at least one active process has been found
#
_check_processes()
{
	RVALUE=1
	NUMPROC=0
	CHECK=0

	# check for each given command name in LOADPROCNAMES if it is currently stated active in "top"
	# i found, that for smbd, proftpd, nsfd, ... there are processes always present in "ps" or "top" output
	# this could be due to the "daemon" mechanism... Only chance to identify there is something happening with these
	# processes, is to check if "top" states them active -> "-I" parameter on the command line
	for LPROCESS in ${LOADPROCNAMES//,/ } ; do
		LP=0
		IPROC=0
		for ((N=0;N < ${LPREPEAT};N++ )) ; do
			_ident_num_proc ${STOPPARAM} ${LPROCESS}
			RESULT=$?
			LP=$(($LP|$RESULT))
			[ $RESULT -gt 0 ] && let IPROC++
		done
		let NUMPROC=$NUMPROC+$LP

		if $DEBUG ; then 
			{ [ $LP -gt 0 ] && _log "DEBUG: _check_processes(): Found active process $LPROCESS"; }
			_log "DEBUG: _check_processes(): > $LPROCESS: found $IPROC of $LPREPEAT cycles active"
		fi

	done   # > LPROCESS in ${LOADPROCNAMES//,/ } ; do

	if ! $DEBUG ; then { [ $NUMPROC -gt 0 ] && _log "INFO: Found $NUMPROC active processes in $LOADPROCNAMES" ; }; fi

	# check for each given command name in TEMPPROCNAMES if it is currently stated present in "top"
	# i found, that for sshd, ... there are processes only present in "ps" or "top" output when is is used.
	# it can not be guaranteed, that top states these services active, as they usually wait for user input
	# no "-I" parameter on the command line, but shear presence is enough
	for TPROCESS in ${TEMPPROCNAMES//,/ } ; do
		TP=0
		IPROC=0
		for ((N=0;N < ${TPREPEAT};N++ )) ; do
			_ident_num_proc ${CTOPPARAM} ${TPROCESS}
			RESULT=$?
			TP=$(($TP|$RESULT))
			[ $RESULT -gt 0 ] && let IPROC++
		done

		let CHECK=$CHECK+$TP

		if ! $DEBUG ; then { [ $TP -gt 0 ] && _log "INFO: _check_processes(): Found active process $TPROCESS"; }; fi

		if $DEBUG ; then _log "DEBUG: _check_processes(): > $TPROCESS: found $IPROC of $TPREPEAT cycles active"; fi

	done   # > for TPROCESS in ${TEMPPROCNAMES//,/ } ; do

	if ! $DEBUG ; then { [ $CHECK -gt 0 ] &&_log "INFO: Found $CHECK active processes in $TEMPPROCNAMES" ; }; fi

	let NUMPROC=$NUMPROC+$CHECK

	if $DEBUG ; then _log "DEBUG: _check_processes(): $NUMPROC process(es) active."; fi

	# only return we found a process
	return $NUMPROC

}

################################################################
#
#   name         : _check_autounrar
#   parameter      : none
#   global return   : none
#   return         : 1      : if process has not been checked or found active
#               : 0      : if process has been found active
#
_check_autounrar()
{
	RVALUE=1

	# check for each given command name in LOADPROCNAMES if it is currently stated active in "top"
	# i found, that for smbd, proftpd, nsfd, ... there are processes always present in "ps" or "top" output
	# this could be due to the "daemon" mechanism... Only chance to identify there is something happening with these
	# processes, is to check if "top" states them active -> "-I" parameter on the command line

	if $DEBUG ; then 
		_log "DEBUG: _check_autounrar(): cat $UNRARLOGDIR/$UNRARLOG = $(cat $UNRARLOGDIR/$UNRARLOG)"
		_log "DEBUG: _check_autounrar(): AUTOUNRARCHECK is running now"
	fi

	if [ -f $UNRARLOGDIR/$UNRARLOG ]; then
		if [ "$(cat $UNRARLOGDIR/$UNRARLOG)" = "processing job" ]; then
			_log "INFO: _check_autounrar(): unrar-script running - no shutdown."
			let RVALUE--
		fi
	fi

	if $DEBUG ; then _log "DEBUG: _check_autounrar(): RVALUE: $RVALUE" ; fi

	return ${RVALUE}

}


################################################################
#
#   name         : _check_statusfile
#   parameter      : none
#   global return   : none
#   return         : 1      : if *.status-File has not been checked or found
#               : 0      : if file has been found
#
_check_statusfile()
{
	RVALUE=1

	# check for each *.status-File in given Dir. If any *.status-File is found, return 0, otherwise 1

	if $DEBUG ; then 
		_log "DEBUG: _check_statusfile(): ls $STATUSFILEDIR *.status"
		_log "DEBUG: _check_statusfile(): _check_statusfile is running now"
	fi

	if [ -f $STATUSFILEDIR/*.status ]; then
		STATUSFILES="$(ls $STATUSFILEDIR *.status)"
        _log "INFO: _check_statusfile(): status-file found - no shutdown."
		if $DEBUG ; then _log "DEBUG: _check_statusfile(): STATUSFILES: $STATUSFILES" ; fi
		let RVALUE--
	fi

	if $DEBUG ; then _log "DEBUG: _check_statusfile(): RVALUE: $RVALUE" ; fi

	return ${RVALUE}
}

################################################################
#
#   name         : _check_net_status
#   parameter      : Array-Nr. of NIC
#   global return   : none
#   return         : 1      : if no active socket has been found
#               : 0      : if at least one active socket has been found
#
_check_net_status()
{
	RVALUE=1
	NUMPROC=0
	NWADAPTERNR_NETSTATUS="$1"
	
	_log "INFO: Check Connections for '${NWADAPTER[${NWADAPTERNR_NETSTATUS}]}'"

	# check for each given socket number in NSOCKETNUMBERS if it is currently stated active in "netstat"
	for NSOCKET in ${NSOCKETNUMBERS//,/ } ; do
		LP=0
		WORD="${CLASS[$NWADAPTERNR_NETSTATUS]}.${SERVERIP[$NWADAPTERNR_NETSTATUS]}:$NSOCKET"
		echo "WORD: $WORD"

		# NETSTATWORD is not set in autoshutdown.conf (only needed for CLI-testing the script
		if [ -z $NETSTATWORD ]; then 
			if $DEBUG ; then _log "DEBUG: _check_net_status(): netstat -n | grep ESTABLISHED | grep ${WORD}"; fi
			LINES=$(netstat -n | grep ESTABLISHED | grep ${WORD})
		else
			if $DEBUG ; then _log "DEBUG: _check_net_status(): netstat -n | egrep "ESTABLISHED|${NETSTATWORD}" | grep ${WORD}"; fi
			LINES=$(netstat -n | egrep "ESTABLISHED|${NETSTATWORD}" | grep ${WORD})
		fi

		if $DEBUG ; then _log "DEBUG: _check_net_status(): Result: $LINES"; fi # changed LINE in LINES

		#if $DEBUG ; then _log "DEBUG: _check_net_status(): echo ${LINES} | grep -c ${WORD2}"; fi
		RESULT=$(echo ${LINES} | grep -c ${WORD})

		let NUMPROC=$NUMPROC+$RESULT

		if $DEBUG ; then _log "DEBUG: _check_net_status(): Is socket present: $RESULT"; fi

		# Check which IP is connected on the specified Port
		# old:
		# CONIP=$(netstat -an | grep ${WORD1} | echo ${WORD2} | awk '{print $5}'| sed 's/\.[0-9]*$//g' | uniq)

		[[ $(echo ${LINES} | awk '{print $5}') =~ (.*):[0-9]*$ ]] && CONIP=${BASH_REMATCH[1]}

		# Set PORTPROTOCOLL
		### TODO: Read BITTORRENT and BITTORRENT_WEBIF-Port from Config
		case $NSOCKET in
			80|8080)   PORTPROTOCOL="HTTP" ;;
			22)      PORTPROTOCOL="SSH" ;;
			21)      PORTPROTOCOL="FTP" ;;
			139|445)   PORTPROTOCOL="SMB/CIFS" ;;
			3689)      PORTPROTOCOL="DAAP" ;;
			6991)      PORTPROTOCOL="BITTORRENT" ;;
			9091)      PORTPROTOCOL="BITTORRENT_WEBIF" ;;
			49152)      PORTPROTOCOL="UPNP" ;;
			*)      PORTPROTOCOL="unknown" ;;
		esac

		if [ $RESULT -gt 0 ]; then _log "INFO: _check_net_status(): Found active connection on port $NSOCKET ($PORTPROTOCOL) from $CONIP"; fi

	done   # > NSOCKET in ${NSOCKETNAMES//,/ } ; do
		

	if ! $DEBUG ; then { [ $NUMPROC -gt 0 ] && _log "INFO: Found $NUMPROC active sockets in $NSOCKETNUMBERS" ; }; fi

	if $DEBUG ; then _log "DEBUG: _check_net_status(): $NUMPROC socket(s) active on ${NWADAPTER[$NWADAPTERNR_NETSTATUS]}."; fi

	# return the number of processes we found
	return $NUMPROC

}

################################################################
#
#   name         	: _check_clock
#   parameter      	: UPHOURS : range of hours, where system should go to sleep, e.g. 6..20
#   global return   : none
#   return         	: 0      : if actual value of hours is in DOWN range, ready for shutdown
#               	: 1      : if actual value of hours is in UP range, no shutdown
#
_check_clock()
{
	CLOCKOK=true

	if  [[ "$UPHOURS" =~ ^([0-9]{1,2})\.{2}([0-9]{1,2}$) ]]; then
		CLOCKSTART=${BASH_REMATCH[1]}
		CLOCKEND=${BASH_REMATCH[2]}
		CLOCKCHECK=$(date +%H | sed 's/^0//g')
		CLOCKMINUTES=$(date +%M)
		TIMETOSLEEP=0
		SECONDSTOSLEEP=0
		TIMETOSLEEP=0
		if $DEBUG ; then
			_log "DEBUG: _check_clock(): CLOCKOK: $CLOCKOK; CLOCKSTART: $CLOCKSTART ; CLOCKEND: $CLOCKEND "
			_log "DEBUG: _check_clock(): CLOCKCHECK: $CLOCKCHECK "
		fi
		_log "INFO: Checking the time: stay up or shutdown ..."

		if [[ $CLOCKEND -gt $CLOCKSTART ]]; then
				
				# aktuelle Zeit liegt zwischendrin
				if [[ $CLOCKCHECK -ge $CLOCKSTART && $CLOCKCHECK -lt $CLOCKEND ]]; then
					CLOCKOK=true
					let TIMETOSLEEP=$CLOCKEND-$CLOCKCHECK-1

					if $DEBUG ; then 
						_log "DEBUG: CHECK 1"
						_log "DEBUG: _check_clock(): CLOCKCHECK: $CLOCKCHECK; CLOCKSTART: $CLOCKSTART ; CLOCKEND: $CLOCKEND -> forced to stay up"
					fi
				else 
					CLOCKOK=false
					if $DEBUG ; then
						_log "DEBUG: CHECK 2"
						_log "DEBUG: _check_clock(): CLOCKCHECK: $CLOCKCHECK; CLOCKSTART: $CLOCKSTART ; CLOCKEND: $CLOCKEND -> shutdown-check"
					fi
				fi
		else
				if [[ $CLOCKCHECK -ge $CLOCKSTART || $CLOCKCHECK -lt $CLOCKEND ]]; then
					CLOCKOK=true
					let TIMETOSLEEP=$CLOCKEND-$CLOCKCHECK-1
					if $DEBUG ; then 
						_log "DEBUG: CHECK 3"
						_log "DEBUG: _check_clock(): CLOCKCHECK: $CLOCKCHECK; CLOCKSTART: $CLOCKSTART ; CLOCKEND: $CLOCKEND -> forced to stay up"
					fi
				else
					CLOCKOK=false
					if $DEBUG ; then 
						_log "DEBUG: CHECK 4"
						_log "DEBUG: _check_clock(): CLOCKCHECK: $CLOCKCHECK; CLOCKSTART: $CLOCKSTART ; CLOCKEND: $CLOCKEND -> shutdown-check"
					fi
				fi
		fi # > [[ $CLOCKEND -gt $CLOCKSTART ]]; then
	fi # > [[ "$UPHOURS" =~ ^([0-9]{1,2})\.{2}([0-9]{1,2}$) ]]; then

	# Calculating the time before shutdown-Phase
	if [ $TIMETOSLEEP -gt 0 ]; then # only if $TIMETOSLEEP > 0; otherwise calculations are obsolete
		let SECONDSTOSLEEP=$TIMETOSLEEP*3600
		let MINUTESTOSLEEP=60-$CLOCKMINUTES-5 # Minutes until full Hour minus 5 min
		let SECONDSTOSLEEP=$SECONDSTOSLEEP+$MINUTESTOSLEEP*60 # Seconds until 5 minutes before shutdown-Range
		
		# The following two should point to shutdown-range minus 5 minutes
		let TIMEHOUR=$CLOCKCHECK+$TIMETOSLEEP # actual time plus hours to sleep 
		let TIMEMINUTES=$CLOCKMINUTES+$MINUTESTOSLEEP # actual time (minutes) plus minutes to sleep
	fi

	if $DEBUG; then
		_log "DEBUG: TIMETOSLEEP: $TIMETOSLEEP"
		_log "DEBUG: SECONDSTOSLEEP: $SECONDSTOSLEEP"
		_log "DEBUG: MINUTESTOSLEEP: $MINUTESTOSLEEP"
		_log "DEBUG: Final: SECONDSTOSLEEP: $SECONDSTOSLEEP"
		_log "DEBUG: TIMEHOUR: $TIMEHOUR - TIMEMINUTES: $TIMEMINUTES"
	fi

	if $CLOCKOK; then
		_log "INFO: System is in Stayup-Range. No need to do anything. Sleeping ..."
		_log "INFO: Sleeping until $TIMEHOUR:$TIMEMINUTES -> $SECONDSTOSLEEP seconds"
		sleep $SECONDSTOSLEEP
		return 1
	else
		_log "INFO: System is in Shutdown-Range. Do further checks ..."
		return 0
	fi
   
}

################################################################
#
#   name         : _check_system_active
#   parameter      : ACTIVEIPS : list of all active IPs found
#   global return   : none
#   return         : 0      : if no active host has been found
#               : 1      : if at least one active host has been found
#
_check_system_active()
{
	# Set CNT to 1, because if $CHECKCLOCKACTIVE is successfull or not active, $CNT will be 0
	CNT=1
	LACTIVEIPS=$1

	# PRIO 0: Do a check, if the actual time is wihin the range of defined STAYUP-phase for this system
	# e.g. 06:00 - 20:00, stay up, otherwise shutdown
	# then: no need to ping all PCs

	if $CHECKCLOCKACTIVE ; then # when $CHECKCLOCKACTIVE is on, then check the Clock

		# if the Clock is in the given Range to shutdown
		#_check_clock $UPHOURS &&
		_check_clock &&
			{
				CNT=0
			}
					
			if $DEBUG ; then _log "DEBUG: _check_clock(): call _check_clock -> CNT: $CNT; UPHOURS: $UPHOURS "; fi

	else
		# If $CHECKCLOCKACTIVE is off, then Begin with CNT=0 and ping 
		CNT=0
		if $DEBUG; then _log "DEBUG: _check_clock is inactive. Setting CNT=0"; fi
	fi # > if $CHECKCLOCKACTIVE ; then

	# call array 1 - $NWADAPTERNR (value is set after scriptstart)
	for NWADAPTERNR_CHECKSYSTEMACTIVE in $(seq 1 $NWADAPTERNR); do

		# if NIC is set (not empty) then check IPs connections, else skip it
		if [ ! -z "${NWADAPTER[$NWADAPTERNR_CHECKSYSTEMACTIVE]}" ]; then
			[[ $DEBUG ]] && _log "DEBUG: _check_system_active is running - Nr. $NWADAPTERNR_CHECKSYSTEMACTIVE"

			if [ $CNT -eq 0 ]; then
				## PRIO 1: Ping each IP address in parameter list. if we find one -> CNT != 0 we'll
				# stop as there's really no point continuing to looking for more.
				_ping_range $NWADAPTERNR_CHECKSYSTEMACTIVE
				PINGRANGERETURN="$?"
				if [ "$PINGRANGERETURN" -gt 0 ]; then
					{	_log "DEBUG: _ping_range -> RETURN: $PINGRANGERETURN"
						let CNT++
					}
				fi
			fi

			#if $DEBUG ; then _log "DEBUG: _check_system_active(): call _check_active_iplist -> CNT: $CNT "; fi
			if $DEBUG ; then _log "DEBUG: _check_system_active(): call _ping_range -> CNT: $CNT "; fi


			if [ $CNT -eq 0 ]; then
			# PRIO 2: Do a check for some active network sockets, maybe, one never knows...
			# If there is at least one active, we leave this function with a 'bogus find'
				_check_net_status $NWADAPTERNR_CHECKSYSTEMACTIVE
				if [ $? -gt 0 ]; then
					let CNT++
				fi

				if $DEBUG ; then _log "DEBUG: _check_system_active(): call _check_net_status -> CNT: $CNT "; fi

			fi   # > if[ $CNT -eq 0 ]; then

		fi # >  if [ ! -z "${NWADAPTER[$NWADAPTERNR_CHECKSYSTEMACTIVE]}" ]; then
	done  # > NWADAPTERNR_CHECKSYSTEMACTIVE in $(seq 1 $NWADAPTERNR); do

	if [ $CNT -eq 0 ]; then
		# PRIO 3: Do a check for some active processes, maybe, one never knows...
		# If there is at least one active, we leave this function with a 'bogus find'
		_check_processes
		if [ $? -gt 0 ]; then
			let CNT++
		fi

		if $DEBUG ; then _log "DEBUG: _check_system_active(): call _check_processes -> CNT: $CNT "; fi

	fi   # > if[ $CNT -eq 0 ]; then


	if [ $CNT -eq 0 ]; then
		# PRIO 4: Do a check for autounrar script active, maybe, one never knows...
		# Only do this when activated by setting $AUTOUNRARCHECK="true" in configuration
		# If this is active, we leave this function with a 'bogus find'
		if [ "$AUTOUNRARCHECK" = "true" ]; then
			_check_autounrar &&
				{
				let CNT++
				}

			if $DEBUG ; then _log "DEBUG: _check_system_active(): call _check_autounrar -> CNT: $CNT "; fi

		fi

	fi   # > if[ $CNT -eq 0 ]; then

	if [ $CNT -eq 0 ]; then
		# PRIO 5: Do a check for any *.status-File in the given directory
		if [ "$STATUSFILECHECK" = "true" ] ; then
			_check_statusfile &&
				{
				let CNT++
				}

			if $DEBUG ; then _log "DEBUG: _check_system_active(): call _check_statusfile -> CNT: $CNT "; fi

		fi

	fi   # > if[ $CNT -eq 0 ]; then

	return ${CNT};
}

###############################################################
######## START OF BODY FUNCTION SCRIPT AUTOSHUTDOWN.SH ########
###############################################################


logger -s -t "$(date '+%b%e - %H:%M:%S'): $USER - : $(basename "$0" | sed 's/\.sh$//g')[$$]" -p $FACILITY.info "INFO: ' XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'"
logger -s -t "$(date '+%b%e - %H:%M:%S'): $USER - : $(basename "$0" | sed 's/\.sh$//g')[$$]" -p $FACILITY.info "INFO: ' X Version: $VERSION'"
logger -s -t "$(date '+%b%e - %H:%M:%S'): $USER - : $(basename "$0" | sed 's/\.sh$//g')[$$]" -p $FACILITY.info "INFO: ' Initialize logging to $FACILITY'"

# #### Reading Config-Variables ####
# #XMLVARIABLES="$(xmlstarlet el /etc/openmediavault/config.xml | egrep '/' | sed 's/.*\///g')"
# XMLVARIABLES="$(xmlstarlet el -v /etc/openmediavault/config.xml | grep autoshutdown | sed 's/autoshutdown//g; s/.*\///g' | grep -v enable)"
# 
# for CONFIGVARIABLES in $XMLVARIABLES; do
#     #echo "-----------------------------------"
# 
# 	# Change Variables to UPPER-Case (needed in this script)
#     VARIABLEUPPER="$(echo $CONFIGVARIABLES | tr '[:lower:]' '[:upper:]')"
#     eval $VARIABLEUPPER=\"$(xmlstarlet sel -t -m //config/services/autoshutdown -v "$CONFIGVARIABLES" /etc/openmediavault/config.xml)\"
#     echo "Die Variable $VARIABLEUPPER hat den Wert $(eval echo \"\$$VARIABLEUPPER\")"
# done

if [ -f /etc/autoshutdown.conf ]; then
	. /etc/autoshutdown.conf
	_log "INFO: /etc/shutdown.conf loaded"
else
	_log "WARN: cfg-File not found! Please check Path /usr/local/bin for autoshutdown.conf"
	exit 1
fi

if [ "$VERBOSE" = "true" ]; then 
	DEBUG="true"
else
	DEBUG="false"
fi

# Read IP-Adress and SERVERIP from 'ifconfig eth0'
### TODO: Make other NW-adapters (bonding) work

# If SERVERIP and CLASS is uncommented in autoshutdown.conf skip reading it from ifconfig

# Removed for auto-config NW-Adapters
#if [ -z "$SERVERIP" -a -z "$CLASS" ]; then
	_log "INFO: Reading NICs ,IPs, ..."
	NWADAPTERNR=0
	FOUNDIP=0
	for NWADAPTERS in bond0 eth0 eth1; do	
		let NWADAPTERNR++
		NWADAPTER[$NWADAPTERNR]=$NWADAPTERS
		
		if ip link show up | grep $NWADAPTERS > /dev/null; then 
			_log "INFO: NIC found: '$NWADAPTERS' - try to get IP"
			IPFROMIFCONFIG[$NWADAPTERNR]="$(ifconfig $NWADAPTERS | grep -e "\(inet\).*Bcast.*" | awk '{print $2}' | sed 's/[^0-9.]//g')"
			SERVERIP[$NWADAPTERNR]="$(echo ${IPFROMIFCONFIG[$NWADAPTERNR]} | sed 's/.*\.//g')"
			CLASS[$NWADAPTERNR]="$(echo ${IPFROMIFCONFIG[$NWADAPTERNR]} | sed 's/\(.*\..*\..*\)\..*/\1/g')"

			#if $DEBUG; then 
				#_log "DEBUG: NWADAPTERS: $NWADAPTERS"
				_log "DEBUG: IPFROMIFCONFIG$NWADAPTERNR: ${IPFROMIFCONFIG[$NWADAPTERNR]}"
				_log "DEBUG: SERVERIP$NWADAPTERNR: ${SERVERIP[$NWADAPTERNR]}"
				_log "DEBUG: CLASS$NWADAPTERNR: ${CLASS[$NWADAPTERNR]}"
			#fi

			# if both variables found, then count 1 up
			if [ ! -z "${SERVERIP[$NWADAPTERNR]}" ] && [ ! -z "${CLASS[$NWADAPTERNR]}" ]; then
				let FOUNDIP++
				
				# bond0 has priority, even if there are eth0 and eth1
				if [ "$NWADAPTERS" = "bond0" ]; then
					_log "INFO: NIC '$NWADAPTERS' found, skipping all others. bond0 has priority"
					break
				fi
			fi

			# Check CLASS and SERVERIP if they are correct
			[[ "${CLASS[$NWADAPTERNR]}" =~ ^(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)\.(25[0-5]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9]|0)$ ]] || { 
				_log "WARN: Invalid parameter format: Class: nnn.nnn.nnn]"
				_log "WARN: It is set to '${CLASS[$NWADAPTERNR]}', which is not a correct syntax. Maybe parsing 'ifconfig ' did something wrong"
				#_log "WARN: Uncomment the CLASS- and SERVERIP-Line in /etc/autoshutdown.conf and change it to your needs to bypass this error"
				_log "WARN: Please report this Bug and the CLI-output of 'ifconfig'"
				_log "WARN: exiting ..."
				exit 1; }

			[[ "${SERVERIP[$NWADAPTERNR]}" =~ ^(25[0-4]|2[0-4][0-9]|[0-1]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[1-9])$ ]] || { 
				_log "WARN: Invalid parameter format: SERVERIP [iii]"
				_log "WARN: It is set to '${SERVERIP[$NWADAPTERNR]}', which is not a correct syntax. Maybe parsing 'ifconfig' did something wrong"
				#_log "WARN: Uncomment the CLASS- and SERVERIP-Line in autoshutdown.conf and change it to yur needs to bypass this error"
				_log "WARN: Please report this Bug and the CLI-output of 'ifconfig'"
				_log "WARN: exiting ..."
				exit 1; }
		
		else
			_log "INFO: NIC '$NWADAPTERS' not found, skipping '$NWADAPTERS'"
			unset NWADAPTER[$NWADAPTERNR]
		fi
	done

	if [ $FOUNDIP = 0 ]; then
		_log "WARN: No SERVERIP or CLASS found"
# 		_log "WARN: Please check the config!"
 		_log "WARN: exiting ..."
 		exit 1
	fi

#else 
# 	if [ -z "$SERVERIP" o -z "$CLASS" ]; then
# 		_log "WARN: Either SERVERIP or CLASS is not configured in /autoshutdown.conf"
# 		_log "WARN: Please check the config!"
# 		_log "WARN: exiting ..."
# 		exit 1
# 	fi
#fi

# echo "Script ends here for testing new Code (NW-Adapters)"
# exit 0


## Check Parameters from Config and setting default variables:
_log "INFO: Checking config"

# Code for XML-Reading from OMV-Config
# if [ ! -z "$AUTOUNRARCHECK" ]; then
# 	case $AUTOUNRARCHECK in
# 		0)
# 			AUTOUNRARCHECK="false";;
# 		1)
# 			AUTOUNRARCHECK="true";;
# 		*)
# 			_log "WARN: AUTOUNRARCHECK not set properly. It has to be '1' (on) or '0' (off)."
# 			_log "WARN: Set AUTOUNRARCHECK to '0' (off)"
# 			AUTOUNRARCHECK="false";;
# 	esac
# fi
# 
# if [ ! -z "$STATUSFILECHECK" ]; then
# 	case $STATUSFILECHECK in
# 		0)
# 			STATUSFILECHECK="false";;
# 		1)
# 			STATUSFILECHECK="true";;
# 		*)
# 			_log "WARN: STATUSFILECHECK not set properly. It has to be '1' (on) or '0' (off)."
# 			_log "WARN: Set STATUSFILECHECK to '0' (off)"
# 			STATUSFILECHECK="false";;
# 	esac
# fi
# 
# case $CHECKCLOCKACTIVE in
# 	0)
# 		CHECKCLOCKACTIVE="false";;
# 	1)
# 		CHECKCLOCKACTIVE="true";;
# 	*)
# 		_log "WARN: CHECKCLOCKACTIVE not set properly. It has to be '1' (on) or '0' (off)."
# 		_log "WARN: Set CHECKCLOCKACTIVE to '0' (off)"
# 		CHECKCLOCKACTIVE="false";;
# esac

if [ ! -z "$AUTOUNRARCHECK" ]; then
	[[ "$AUTOUNRARCHECK" = "true" || "$AUTOUNRARCHECK" = "false" ]] || { _log "WARN: AUTOUNRARCHECK not set properly. It has to be 'true' or 'false'."
			_log "WARN: Set AUTOUNRARCHECK to false"
			AUTOUNRARCHECK="false"; }
fi

if [ ! -z "$STATUSFILECHECK" ]; then
	[[ "$STATUSFILECHECK" = "true" || "$STATUSFILECHECK" = "false" ]] || { _log "WARN: STATUSFILECHECK not set properly. It has to be 'true' or 'false'."
			_log "WARN: Set STATUSFILECHECK to false"
			STATUSFILECHECK="false"; }
fi

[[ "$CHECKCLOCKACTIVE" = "true" || "$CHECKCLOCKACTIVE" = "false" ]] || { _log "WARN: CHECKCLOCKACTIVE not set properly. It has to be 'true' or 'false'."
		_log "WARN: Set CHECKCLOCKACTIVE to false"
		CHECKCLOCKACTIVE="false"; }



[[ "$FLAG" =~ ^[0-9]{1,3}$ ]] || { 
		_log "WARN: Invalid parameter format: Flag"
		_log "WARN: You set it to '$FLAG', which is not a correct syntax. Maybe it's empty?"
		_log "WARN: Setting FLAG to 5"
		FLAG="5"; }
[[ "$UPHOURS" =~ ^(([0-1]?[0-9]|[2][0-3])\.{2}([0-1]?[0-9]|[2][0-3]))$ ]] || { 
		_log "WARN: Invalid parameter list format: UPHOURS [hour1..hour2]"
		_log "WARN: You set it to '$UPHOURS', which is not a correct syntax. Maybe it's empty?"
		_log "WARN: Setting UPHOURS to 6..20"
		UPHOURS="6..20"; }

if [ -z "$NETSTATWORD" ]; then 
	if $DEBUG; then
		_log "INFO: NETSTATWORD not set in the config. The check for connections, like SSH (Port 22) will not work on the CLI until you set NETSTATWORD"
		_log "INFO: If you run this sript at systemstart with init.d it will work as expected"
		_log "INFO: Read the README for further Infos"
	fi
else
	[[ "$NETSTATWORD" =~ ^(A-Z)$ ]] || { 
		_log "WARN: Invalid parameter list format: NETSTATWORD [A-Z]"
		_log "WARN: You set it to '$NETSTATWORD', which is not a correct syntax."
		_log "WARN: Unsetting NETSTATWORD"
		unset NETSTATWORD; }
fi

# Had to define REGEX here, because the script doesn't work from systemstart, but from the CLI (WTF?)
REGEX="^([A-Za-z0-9_\.-]{1,})+(,[A-Za-z0-9_\.-]{1,})*$"
if  [ "$LOADPROCNAMES" = "" ]; then
        _log "INFO: LOADPROCNAMES is empty - No processes being checked"
else
        [[ "$LOADPROCNAMES" =~ $REGEX ]] || { 
                _log "WARN: Invalid parameter list format: LOADPROCNAMES [lproc1,lproc2,lproc3,...]"
                _log "WARN: You set it to '$LOADPROCNAMES', which is not a correct syntax."
                _log "WARN: exiting ..."
                exit 1; }
fi

if  [ "$TEMPPROCNAMES" = "" ]; then
	_log "INFO: TEMPPROCNAMES is emtpy - No temp-processes being checked"
else
	[[ "$TEMPPROCNAMES" =~ $REGEX ]] || { 
		_log "WARN: Invalid parameter list format: TEMPPROCNAMES [tproc1,tproc2,tproc3,...]"
		_log "WARN: You set it to '$TEMPPROCNAMES', which is not a correct syntax."
		_log "WARN: exiting ..."
		exit 1; }	
fi

[[ "$NSOCKETNUMBERS" =~ ^[0-9]{1,5}|[[0-9]{1,5}\,]$ ]] || { 
		_log "WARN: Invalid parameter list format: NSOCKETNUMBERS [nsocket1,nsocket2,nsocket3,...]"
		_log "WARN: You set it to '$NSOCKETNUMBERS', which is not a correct syntax. Maybe it's empty?"
		_log "WARN: Setting NSOCKETNUMBERS to 22 (SSH)"
		NSOCKETNUMBERS="22"; }

if [ -z $PINGLIST ]; then
	[[ "$RANGE" =~ ^([1-9]{1}[0-9]{0,2})?([1-9]{1}[0-9]{0,2}\.{2}[1-9]{1}[0-9]{0,2})?(,[1-9]{1}[0-9]{0,2})*((,[1-9]{1}[0-9]{0,2})\.{2}[1-9]{1}[0-9]{0,2})*$ ]] || { 
			_log "WARN: Invalid parameter list format: RANGE [v..v+n,w,x+m..x,y,z..z+o]"
			_log "WARN: You set it to '$RANGE', which is not a correct syntax."
			_log "WARN: Setting RANGE to 2..254"
			RANGE="2..254"; }
else
	if [ -f "$PINGLIST" ]; then
		_log "INFO: PINGLIST is set in the conf, reading IPs from it"
		USEOWNPINGLIST="true"
	else
		_log "WARN: PINGLIST is set in the conf, but the file isn't there"
		_log "WARN: Setting RANGE to 2..254"
		RANGE="2..254"
	fi
fi

[[ "$SLEEP" =~ ^[0-9]{1,3}$ ]] || { _log "WARN: Invalid parameter format: SLEEP (sec)"
		_log "WARN: You set it to '$SLEEP', which is not a correct syntax. Maybe it's empty?"
		_log "WARN: Setting SLEEP to 180 sec"
		SLEEP=180; }

#### Testing fping ####
if ! which fping > /dev/null; then
	echo "WARN: fping not found! Please install it with 'apt-get install fping'"
	_log "WARN: fping not found! Please install it with 'apt-get install fping'"
	exit 1
fi

# If the pinglist or pinglistactive exists, delete it (at every start of the script)
if [ -f /tmp/pinglist ]; then
	rm -f /tmp/pinglist 2> /dev/null
	[[ $? = 0 ]] && _log "INFO: Pinglist deleted" || _log "WARN: Can not delete Pinglist!"
fi

# Init the counter
FCNT=$FLAG

# functional start of script
if $DEBUG ; then
	_log "INFO:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	_log "DEBUG: ### DEBUG:"
	#_log "DEBUG: CLASS: $CLASS"
 	#_log "DEBUG: SERVERIP: $SERVERIP"
	_log "DEBUG: CLASS and SERVERIP: see above"
	_log "DEBUG: FLAG: $FLAG"
	_log "DEBUG: SLEEP: $SLEEP"
	_log "DEBUG: CHECKCLOCKACTIVE: $CHECKCLOCKACTIVE"
	_log "DEBUG: UPHOURS: $UPHOURS"
	_log "DEBUG: RANGE: $RANGE"
	_log "DEBUG: LOADPROCNAMES: $LOADPROCNAMES"
	_log "DEBUG: NSOCKETNUMBERS: $NSOCKETNUMBERS"
	_log "DEBUG: TEMPPROCNAMES: $TEMPPROCNAMES"
	_log "DEBUG: AUTOUNRARCHECK: $AUTOUNRARCHECK"
	_log "DEBUG: UNRARLOGDIR: $UNRARLOGDIR"
	_log "DEBUG: UNRARLOG: $UNRARLOG"
	_log "DEBUG: STATUSFILECHECK: $STATUSFILECHECK"
	_log "DEBUG: STATUSFILEDIR: $STATUSFILEDIR"
	_log "DEBUG: VERBOSE: $VERBOSE"
fi   # > if $DEBUG ;then

_log "INFO:---------------- script started ----------------------"
_log "INFO: ${FLAG} test cycles until shutdown is issued."
_log "INFO: network range is given within \"$RANGE\"."

for NWADAPTERNR_START in $(seq 1 $NWADAPTERNR); do
	
	# if NIC is set (not empty) then check IPs connections, else skip it
	if [ ! -z "${NWADAPTER[$NWADAPTERNR_START]}" ]; then
		_log "INFO: script is doing checks for NIC: ${NWADAPTER[$NWADAPTERNR_START]} - ${CLASS[$NWADAPTERNR_START]}.${SERVERIP[$NWADAPTERNR_START]}"
	fi
done

#_log "INFO: retrieve list of active IPs for the first time ..."

# # retrieve all currently active IPs in your network # at first Start of the script
# # if there has none active found try again after $SLEEP seconds in next execution cycle
# for NWADAPTERNR_FIRSTPING in $(seq 1 $NWADAPTERNR); do
# 	
# 	# if NIC is set (not empty) then check IPs connections, else skip it
# 	if [ ! -z "${NWADAPTER[$NWADAPTERNR_FIRSTPING]}" ]; then
# 		_ping_range $NWADAPTERNR_FIRSTPING
# 	fi
# done
# 
# 
# #RESULT=$?
# 
# if $DEBUG ; then
# 	for IP in $ACTIVEIPS ; do
# 		_log "DEBUG: > IP ${IP} currently active."
# 	done
# fi   # > if $DEBUG ; then

while : ; do
	_log "INFO:------------------------------------------------------"
	_log "INFO: new supervision cycle started."

	# Main loop, just keep pinging and checking for processes, to decide whether we can shutdown or not...
	_log "INFO: check number of active hosts in configured network range..."

	if _check_system_active $ACTIVEIPS ; then

			# Nothing found so sub one from the count and check if we can shutdown yet.
			let FCNT--

			_log "INFO: No active processes or hosts within network range, ${FCNT} cycles until shutdown..."

			if [ $FCNT -eq 0 ]; then
				_shutdown;
			fi   # > if [ $FCNT -eq 0 ]; then
	else
		# Live IP found so reset count
		FCNT=${FLAG};
	fi   # > if _check_system_active

	# Wait for the required time before checking again.
	_log "INFO: sleep for ${SLEEP}s."
	sleep $SLEEP;

done   # > while : ; do

echo "This should not happen!" && exit 42
#EOF####### END OF SCRIPT AUTOSHUTDOWN.SH ########
