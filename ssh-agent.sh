#!/bin/sh
# ssh-agent.sh is a sh/bash/zsh compatible script sourced from /etc/profile.d/
# at user login. It reads configuration from /etc/ssh/ssh-agent.conf 
# or ~/.ssh/ssh-agent.conf if any exist and, depending on settings 
# in configuration file, runs ssh-agent with given options at first user login,
# exports SSH_AGENT_PID SSH_AUTH_SOCK environment variables to all login 
# sessions. If ssh-agent is already started for given user, script exports only
# SSH_AGENT_PID SSH_AUTH_SOCK to new user's login session.

[ -f /etc/ssh/ssh-agent.conf ] && SSH_AGENT_CONF="/etc/ssh/ssh-agent.conf"
[ -f "${HOME}/.ssh/ssh-agent.conf" ] && SSH_AGENT_CONF="${HOME}/.ssh/ssh-agent.conf"
if [ -s "$SSH_AGENT_CONF" ] ; then
	. "$SSH_AGENT_CONF" || :
	if [ "$ssh_agent_enable" = "yes" -o "$ssh_agent_enable" = "YES" ] ; then
		SSH_AGENT_DATA="${HOME}/.ssh/SSH-AGENT-DATA"
		if [ -s "$SSH_AGENT_DATA" ] ; then
        		. "$SSH_AGENT_DATA" > /dev/null
		        if [ "$(ps uhp "$SSH_AGENT_PID" 2>/dev/null | awk '$1 ~ ENVIRON["USER"] {print $11}')" != "ssh-agent" ] ; then
        		        ssh-agent $ssh_agent_flags > "$SSH_AGENT_DATA" 
		                . "$SSH_AGENT_DATA" > /dev/null
		        fi
		else
		        ssh-agent $ssh_agent_flags > "$SSH_AGENT_DATA" 
		        . "$SSH_AGENT_DATA" > /dev/null
		fi
	fi
fi

