#!/bin/sh
# ssh-agent.sh - linux ver. (make against procps-3.2.1), sh/bash/zsh compatible
# like gnupg-agent-agent.sh (what the long & insane name!?) put this
# in /etc/profile.d/ chmod 755 /etc/profile.d/ssh-agent.sh
# make ln -s /etc/profile.d/ssh-agent.sh /etc/X11/xinit/xinitrc.d/ssh-agent.sh
# echo "ssh_agent_enable=yes" > $HOME/.ssh/ssh-agent.conf and forget about keychain

SSH_AGENT_CONF="${HOME}/.ssh/ssh-agent.conf"
if [ -s "$SSH_AGENT_CONF" ] ; then
	. "$SSH_AGENT_CONF" || :
	if [ "$ssh_agent_enable" = "yes" -o "$ssh_agent_enable" = "YES" ] ; then
		SSH_AGENT_DATA="${HOME}/.ssh/SSH-AGENT-DATA"
		if [ -s "$SSH_AGENT_DATA" ] ; then
        		. "$SSH_AGENT_DATA" > /dev/null
		        if [ "$(ps -p "$SSH_AGENT_PID" | tail -n1 | awk '{print $4}')" != "ssh-agent" ] ; then
        		        ssh-agent > "$SSH_AGENT_DATA" 2>&1
		                . "$SSH_AGENT_DATA" > /dev/null
		        fi
		else
		        ssh-agent > "$SSH_AGENT_DATA" 2>&1
		        . "$SSH_AGENT_DATA" > /dev/null
		fi
	fi
fi

