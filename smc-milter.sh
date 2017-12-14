#!/bin/sh

# PROVIDE: smc_milter
# REQUIRE: LOGIN cleanvar 
# BEFORE: sendmail
# KEYWORD: smc-milter 

# Add the following line to /etc/rc.conf to enable smc-milter:
#
# smc_milter_enable="YES"
# 

. /etc/rc.subr

name="smc_milter"
rcvar=`set_rcvar`

load_rc_config $name

: ${smc_milter_enable="NO"}

command=/usr/local/sbin/smc-milter
pidfile=/var/run/smc-milter.pid
required_files=/usr/local/etc/smc-milter.conf
stop_postcmd=stop_postcmd
extra_commands="reload"

stop_postcmd()
{
    rm -f $pidfile
}

run_rc_command "$1"
