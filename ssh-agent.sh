#!/bin/sh
# ssh-agent.sh sh/bash/zsh compatible script for /etc/profile.d/ .
# Works like gnupg-agent-agent.sh . Copy this in /etc/profile.d/ ,
# make ln -s /etc/profile.d/ssh-agent.sh /etc/X11/xinit/xinitrc.d/ssh-agent.sh
# run echo "ssh_agent_enable=yes" > $HOME/.ssh/ssh-agent.conf . 

[ -f /etc/ssh/ssh-agent.conf ] && SSH_AGENT_CONF="/etc/ssh/ssh-agent.conf"
[ -f "${HOME}/.ssh/ssh-agent.conf" ] && SSH_AGENT_CONF="${HOME}/.ssh/ssh-agent.conf"
if [ -s "$SSH_AGENT_CONF" ] ; then
	. "$SSH_AGENT_CONF" || :
	if [ "$ssh_agent_enable" = "yes" -o "$ssh_agent_enable" = "YES" ] ; then
		SSH_AGENT_DATA="${HOME}/.ssh/SSH-AGENT-DATA"
		if [ -s "$SSH_AGENT_DATA" ] ; then
        		. "$SSH_AGENT_DATA" > /dev/null
		        if [ "$(ps -p "$SSH_AGENT_PID" | tail -n1 | awk '{print $4}')" != "ssh-agent" ] ; then
        		        ssh-agent "$ssh_agent_flags" > "$SSH_AGENT_DATA" 2>&1
		                . "$SSH_AGENT_DATA" > /dev/null
		        fi
		else
		        ssh-agent "$ssh_agent_flags" > "$SSH_AGENT_DATA" 2>&1
		        . "$SSH_AGENT_DATA" > /dev/null
		fi
	fi
fi

