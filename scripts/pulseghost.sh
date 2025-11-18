#!/bin/bash
#pulseGhost level 1 MVP script
#pre-attack intrusion prdictor(behavior-based)

set -euo pipefail
#========================PATHS===============================
STATUS_FILE="/var/lib/pulseghost/status.txt"
LOG_DIR="/opt/pulseghost/logs"
LOG_FILE="$LOG_DIR/pulseghost.log"
STATUS_DIR="/var/lib/pulseghost"

#Typical auth log locations(RHEL VS DEBIAN-BASED)
AUTH_LOG_1="/var/log/secure"
AUTH_LOG_2="var/log/auth.log"

mkdir -p "$STATUS_DIR"


if [ ! -d "$LOG_DIR" ]; then 
        mkdir -p "$LOG_DIR"
        restorecon -R "$LOG_DIR"
fi

if [ ! -f "$LOG_FILE" ]; then 
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
        restorecon "$LOG_FILE"
fi

if [ ! -f "$STATUS_FILE" ]; then 
        echo "unknown" > "$STATUS_FILE"
        restorecon "$STATUS_FILE"
fi

#=======================SIMPLE LOGGER============================
log() {
        local message="$1"
        # we are going to print the date in a simpple foramt 
        printf '%s PULSEGHOST: %s\n' "$(date '+%y-%m-%d %H:%M:%S')" "$message" >> "$LOG_FILE"
}

#=====================HELPER: AUTH LOG PATH======================
get_auth_log() {
        if [ -f "$AUTH_LOG_1" ]; then
                echo "$AUTH_LOG_1"
        elif [ -f "$AUTH_LOG_2" ]; then
                echo "$AUTH_LOG_1"
        else #no AUTH log found
                echo ""
        fi
}

#=================SIGNAL COLLECTOR===============================
#failed ssh attempts in last N LINES
check_failed_ssh() {
        local auth_log
        auth_log="$(get_auth_log)"
        if [ -z "$auth_log" ]; then
                echo "0"
                return 0
        fi
# look at last 200 lines for "failed password"
local count 
count=$(tail -n 200 "$auth_log" 2>/dev/null | grep -c "failed password" || true)
echo "$count"
}

# suspicious commands in bash history across all users 
# we scan for very simple patterns only

check_history_signals() {
        local total=0
        # look at all home directories with .bash_history 

for hist_file in /root/.bash_history /home/*/.bash_history; do
        [ -f "$hist_file" ] || continue 

# count some patterns that look like recon / probing 
local c_ls_sensitive c_sudo_probe c_shadow
#ls in critical directories ( reconnaissance-thi means we are checking before we take any action )
c_ls_sensitive=$(grep -E 'ls .*(/etc|/var|/opt|/var/www)' "$hist_file" 2>/dev/null | wc -l || true)

# sudo probing 
c_sudo_probe=$(grep -E 'sudo -l | sudo -v' "$hist_file" 2>/dev/null | wc -l || true)

# direct access to /etc/shadow
c_shadow=$(grep -E '/etc/shadow' "$hist_file" 2>/dev/null | wc -l || true)
total=$(( total + c_ls_sensitive + c_sudo_probe + c_shadow))
done 
echo "$total"
}

# sensitive file acess pattern (very simple grep on /logs / history )
check_sensitive_file_access() {
        local count=0
        #simple heuristic: if /etc/shadow or /etc/passwd is being grepped or cat'd often 
        for hist_file in /root/.bash_history /home/*/.bash_history; do
                [ -f "$hist_file" ] || continue 
                local c 
                c=$(grep -E 'cat /etc/shadow | grep .* /etc/shadow | cat /etc/passwd | grep .* /etc/passwd' "$hist_file" 2>/dev/null | wc -l || true)
                count=$((count + c)) 
        done
        echo "$count"
}


#===============================SCORING ENGINE============================================
calculate_score() {
        local failed_ssh="$1"
        local history_signals="$2"
        local sensitive_access="$3"

        local score=0
# weight 1 : failed ssh 
# 0-2=0 points, 3-5=+2, >5=+4
if [ "$failed_ssh" -ge 3 ] && [ "$failed_ssh" -le 5 ]; then 
        score=$(( score +2 ))
elif [ "$failed_ssh" -gt 5 ]; then 
        score=$(( score +4 ))
fi
#weight :2 recon/suspicious history patterns
#1-3 = +2, 4-10 = +4, >10 = +6
if [ "$history_signals" -ge 1 ] && [ "$history_signals" ]; then 
	score=$(( score + 2 )) 
elif [ "$history_signals" -gt 10 ]; then
	score=$(( score + 6 ))
fi


# weight 3: direct sensitive file access 
# 1-2=+3, >2 =+5
if [ "$sensitive_access" -ge 1 ] && [ "$sensitive_access" -le 2 ]; then 
        score=$(( score +3 ))
elif [ "$sensitive_access" -gt 2 ]; then 
        score=$(( score +5 ))
fi
echo "$score"
}

classify_score() {
        local score="$1"
        if [ "$score" -le 2 ]; then 
                echo "LOW"
        elif [ "$score" -le 5 ]; then 
                echo "MEDIUM"
        else
                echo "HIGH"
        fi
}

#=================MAIN LOGIC================================
main() {
        mkdir -p "$(dirname "$STATUS_FILE")"
        mkdir -p "$LOG_DIR"

        local failed_ssh history_signals sensitive_access

        failed_ssh=$(check_failed_ssh)
        history_signals=$(check_history_signals)
        sensitive_access=$(check_sensitive_file_access)

        local score level 
        score=$(calculate_score "$failed_ssh" "$history_signals" "$sensitive_access")
        level=$(classify_score "$score")

# Build a short human friendly report
{
        echo "===PulseGhost pre-Attack Assesment======"
        echo "Failed ssh attempts(last 200 log lines): $failed_ssh"
        echo "Recon/suspicious history patterns:       $history_signals"
        echo "Sensitive file access patterns:          $sensitive_access"
        echo
        echo "computed risk score:                     $score"
        echo "Risk level:                              $level"
        echo
        echo "Note: level 1MVP uses very simple heristics(pattern-based detection)"
} > "$STATUS_FILE"
 log "Assesment complete:SCORE=$score LEVEL=$level FAILED_SSH=$failed_ssh HISTORY=$history_signals SENSITIVE=$sensitive_access"
}
main "$@"

