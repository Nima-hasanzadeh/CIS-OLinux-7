#!/bin/bash

#Program: Caliper v1.0
#Author: Nima.H 
#OS Support : Oracle Linux 7 (It may be compatible with most Red Hat distributions)
#I'm going to provide a starting point for  Linux admins to build a secure server which meets the CIS standards.
#For more information please check : github.com/Nima-Hasanzadeh

clear

if [ "$EUID" -ne 0 ]
  then
echo -e  "Dear "$USER",Please run this script as root user"
  kill $$
fi


echo -e "\e[91m"
cat <<EOF


 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    ████████╗███████╗ █████╗ ███╗N.H███╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
 ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝        ██║   █████╗  ███████║██╔████╔██║
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝         ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║          ██║   ███████╗██║  ██║██║ ╚═╝ ██║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝          ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
 Caliper 1.0
 Auditing Oracle Linux 7.0
 github.com/Nima-Hasanzadeh

EOF
echo -e "\e[49m"
. /etc/os-release
echo -e "You are running \e[43m\e[34m${PRETTY_NAME}\e[0m\n"
read -p "Press Enter to continue . . ."



 if echo ${PRETTY_NAME} | cut -f1 -d'.' | grep -q "Oracle Linux Server 7"; then
  echo
    else
   echo -e "Your OS release is not supported! You are running \e[43m\e[31m${PRETTY_NAME}\e[0m ,Are you sure you want to proceed?"
  read -p "Do you want to continue? (y/n): " response
    if [ "$response" = "y" ]; then
     echo "Continuing..."
      elif [ "$response" = "n" ]; then
      echo "Exiting the script."
	   kill $$
      else
     echo "Invalid input. Please enter 'y' to continue or 'n' to exit."
	kill $$
   fi
 fi



# Configuration files
MAIN_VERSION_ID="$(echo ${VERSION_ID} |cut -f1 -d'.')"
LOGFILE=log_$(date '+%Y%m%d.%H.%M')
LOGFILE_ERRORS=log_errors_$(date '+%Y%m%d.%H.%M')
IP_ADR=$(nmcli -f IP4.ADDRESS device show | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -n 1)
SYSCTL_60='/etc/sysctl.d/60-kernel_sysctl.conf'
RSYSLOG_CONF='/etc/rsyslog.conf /etc/rsyslog.d/*.conf'
CHRONY_CONF='/etc/chrony.conf'
SYSCTL_CONF='/etc/sysctl.conf  /etc/sysctl.d/*.conf'
SUDOERS='/etc/sudoers* /etc/sudoers.d/*'
PROFILE_D='/etc/profile.d/bash_completion.sh'
AUDIT_TOOLS='/sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules'
AUDIT_DIR='/etc/audit/'
FSTAB='/etc/fstab'
YUM_CONF='/etc/dnf/dnf.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_CFG2='/boot/grub2/user.cfg'
GRUB_ENV='/boot/grub2/grubenv'
GRUB_DIR='/etc/grub.d'
RESCUE_DIR='/usr/lib/systemd/system/rescue.service'
DUMP_DIR='/etc/systemd/coredump.conf'
SELINUX_CFG='/etc/selinux/config'
JOURNALD_CFG='/etc/systemd/journald.conf'
SECURETTY_CFG='/etc/securetty'
LIMITS_CNF='/etc/security/limits.conf'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config'
SYSTEM_AUTH='/etc/pam.d/system-auth'
PASS_AUTH='/etc/pam.d/password-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
GROUP2='/etc/group-'
LOGIN_DEFS='/etc/login.defs'
LIB_USR='/etc/libuser.conf'
PASSWD='/etc/passwd'
PASSWD2='/etc/passwd-'
SHADOW='/etc/shadow'
SHADOW2='/etc/shadow-'
GSHADOW='/etc/gshadow'
GSHADOW2='/etc/gshadow-'
BASHRC='/etc/bashrc'
PROF_D='/etc/profile.d'
PROFILE='/etc/profile'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'
SUDO_CONF='/etc/sudoers'
PAM_SU='/etc/pam.d/su'
SUDOERS='/etc/sudoers*'
FAIL_CONF='/etc/security/faillock.conf'
PWQUAL_CNF='/etc/security/pwquality.conf'
PWHISTORY_CNF='/etc/security/pwhistory.conf'
TOTAL=0
PASS=0
FAILED=0
. /etc/os-release
OS_VERSION="$(echo ${PRETTY_NAME})"
SEC_LIMITS='/etc/security/limits.conf'


function results {

create_bar() {
    local value=$1
    for ((i=1; i<=$value; i++)); do
        printf "#"
    done
    printf "\n"
}

# Display the bar chart
echo_bold "\nThe results are shown as below :"
echo_red "--------------------------------------------------------------------------------------------"
echo_bold    "Total Checks : $TOTAL $(create_bar $(($TOTAL / 10)))"
echo_green   "Passed Items : $PASS $(create_bar $(($PASS / 10)))"
echo_red     "Failed Items : $FAILED  $(create_bar $((($FAILED+9) / 10)))"
echo_yellow  "Failure Percentage : $(expr $FAILED \* 100 / $TOTAL)%"

}


function echo_yellow {
  echo -e "\e[93m${@} \e[0m"
}

function echo_bold {
  echo -e "\e[1m${@} \e[0m"
}

function echo_red {
  echo -e "\e[91m${@} \e[0m"
}

function echo_green {
  echo -e "\e[92m${@} \e[0m"
}


function disable_fs {
  # Test the the supplied filesystem type $1 is disabled

 local module="${1}"
 if  lsmod | grep -q ${module}; then false;else true ; fi || return
 modprobe -n -v ${module} | grep -q "install \+/bin/false" || return
}


function gpg_key_installed {
  # Test GPG Key is installed
  rpm -q gpg-pubkey | grep -q gpg || return
}


function gpg_check {
grep "^repo_gpgcheck=1\b" /etc/dnf/dnf.conf || return
grep "^gpgcheck=1\b" /etc/dnf/dnf.conf || return

}

function single_user_mode {
 local rescue_service=$(grep -Eq "/sbin/sulogin" /usr/lib/systemd/system/rescue.service)
 local emergency_service=$(grep -Eq "/sbin/sulogin|/usr/sbin/sulogin" /usr/lib/systemd/system/emergency.service)

if [[ -n $rescue_service && -n $emergency_service ]]; then return 0; else return 1;fi 

}




function yum_update {
  # Check for outstanding pkg update with yum
  yum -q check-update || return
}

function rpm_installed {
  # Test whether an rpm is installed

  local rpm="${1}"
  local rpm_out
  rpm_out="$(rpm -q --queryformat "%{NAME}\n" ${rpm})"
  [[ "${rpm}" = "${rpm_out}" ]] || return
}

function verify_aide_cron {
  # Verify there is a cron job scheduled to run the aide check
  crontab -u root -l | cut -d\# -f1 | grep -q "aide \+--check" || return
}

function verify_selinux_grubcfg {
  # Verify SELinux is not disabled in grub.cfg file 

  local grep_out1
  grep_out1="$(grep selinux=0 ${GRUB_CFG})"
  [[ -z "${grep_out1}" ]] || return

  local grep_out2
  grep_out2="$(grep enforcing=0 ${GRUB_CFG})"
  [[ -z "${grep_out2}" ]] || return
  
  local grep_out3
  local grep_out3="$(grubby --info=ALL | grep -Po '(selinux|enforcing)=0\b')"
  [[ -z "${grep_out3}" ]] || return

}

function verify_selinux_state {
  # Verify SELinux configured state in /etc/selinux/config

cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUX=' | tr -d '[[:space:]]' | grep -Piq 'SELINUX=(enforcing|permissive)'      || return
}

function verify_selinux_policy {
  # Verify SELinux policy in /etc/selinux/config
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUXTYPE=' | tr -d '[[:space:]]' | grep -q 'SELINUXTYPE=targeted' || return
}



 function disable_sha1 {
   local outlet1="$(grep -Pi -- '^\h*(hash|sign)\h*=\h*([^\n\r#]+)?-sha1\b' /etc/cryptopolicies/state/*.pol)"
   [[ -z ${outlet1} ]] || return
  }
   
 function disable_cbc {
local outlet1="$(grep -Piq -- '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/cryptopolicies/state/*.pol)"
   [[ -z ${outlet1} ]] || return
}

function disable_oldmac {
local outlet1="$(grep -Pi -- '^\h*mac\h*=\h*([^#\n\r]+)?-64\b' /etc/cryptopolicies/state/*.pol)"
   [[ -z ${outlet1} ]] || return
 }

   
 function chrony_user {
  local outlet1="$(grep -Psi -- '^\h*OPTIONS=\"?\h+-u\h+root\b' /etc/sysconfig/chronyd )" 
    [[ -z ${outlet1} ]] || return
 }
 
 

function rpm_not_installed {
  # Check that the supplied rpm $1 is not installed
  local rpm="${1}"
  rpm -q ${rpm} | grep -q "package ${rpm} is not installed" || return
}

function unconfined_procs {
  # Test for unconfined daemons
  local ps_out
  ps_out="$(ps -eZ | egrep 'initrc|unconfined' | egrep -v 'bash|ps|grep')"
  [[ -n "${ps_out}" ]] || return
}

function check_grub_owns {
  # Check User/Group Owner on grub.cfg file
  stat -L -c "%u %g" ${GRUB_CFG} | grep -q '0 0' || return
  stat -L -c "%u %g" ${GRUB_ENV}| grep -q '0 0' || return
  #stat -L -c "%u %g" ${GRUB_CFG2} | grep -q '0 0' || return
  }

#function check_grub_perms {
  # Check Perms on grub.cfg file
 # stat -L -c "%a" ${GRUB_CFG}  | grep -eq '\b700\b'  || return
  #stat -L -c "%a" ${GRUB_ENV}  | grep -eq '\b600\b'  || return
  #stat -L -c "%a" ${GRUB_CFG2} | grep -eq '\b600\b'  || return
  #}

function check_file_perms {
  # Check Perms on a supplied file match supplied pattern
  local file="${1}"
  local pattern="${2}"
  local perms=$(stat -L -c "%#a" "${file}" | rev | cut -c 1-3 | rev )
   if [ "${perms}" -le "${pattern}" ]; then true ; else false;fi || return
}


function check_root_owns {
  # Check User/Group Owner on the specified file
  local file="${1}"
  stat -L -c "%u %g" ${file} | grep -q '0 0' || return
}

function check_boot_pass {
  grep -q 'set superusers=' "${GRUB_CFG}"
  if [[ "$?" -ne 0 ]]; then
    grep -q 'set superusers=' ${GRUB_DIR}/* || return
    file="$(grep 'set superusers' ${GRUB_DIR}/* | cut -d: -f1)"
    grep -q 'password' "${file}" || return
  else
    grep -q 'password' "${GRUB_CFG}" || return
  fi
}

function check_rescue {
#check authentication enabled in rescue mode

grep -q  /systemd-sulogin-shell ${RESCUE_DIR}  || return

}

function chk_mta {
#verify mail transfer agent (MTA) config for local-only mode

 local grep_out1
 local grep_out1="$(ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|\[?::1\]?):25\s')"
 [[ -z "${grep_out1}" ]] || return


}

function check_svc_not_enabled {
  # Verify that the service is not enabled
  local service="$1"
  systemctl is-enabled "${service}" | grep -q 'disabled' || return
  systemctl is-active "${service}" | grep -q "\binactive\b" || return
}

function check_svc_enabled {
  # Verify that the service is enabled
  local service="$1"
  systemctl list-unit-files | grep -q "${service}.service" || return
  systemctl is-enabled "${service}" | grep -q 'enabled' || return
  systemctl is-active "${service}" | grep -q "\bactive\b" || return
}


function chk_journald_enabled {
  # Verify that the service journald is enabled
  local service="$1"
  systemctl is-active "${service}" | grep -q "\bactive\b" || return
  systemctl is-enabled "${service}" | grep -q 'static' || return
}


  
  
function chrony_cfg {
   egrep -q "^(server|pool)" ${CHRONY_CONF} || return
}

function restrict_core_dumps {
  # Ensure core dump storage is disabled 
   grep -i '^\s*storage\s*=\s*none\b' ${DUMP_DIR} || return
}

function restrict_bcktrc_dumps  {
  # Ensure core dump backtraces is disabled 
   grep -i '^\s*ProcessSizeMax\s*=\s*0\b' ${DUMP_DIR} || return
}


function xd_nx {
  journalctl | grep -q "protection: active" || return
}



function chk_network_config {
 local value="$1"
 grep net.ipv $SYSCTL_CONF | tr -d '[[:space:]]' | grep -i  "$value" || return
}

function ipv6_disabled {

grubby --info=ALL | grep -Po "\bipv6.disable=1\b" || return
 for i in "NETWORKING_IPV6=no" "IPV6INIT=no"; do
  egrep -q "^$i" /etc/sysconfig/network || return 1
 done

 [ -f /etc/sysctl.d/60-disable_ipv6.conf ] && egrep -q 'net.ipv6.conf.all.disable_ipv6\s*=\s*1\b' /etc/sysctl.d/60-disable_ipv6.conf || return
local v6="$(ip -6 addr)" ; [[ -z ${v6} ]]  || return

}

function chk_sysctl_cnf {
  # Check the sysctl_conf file contains a particular flag, set to a particular value 
  local flag="$1"
  local value="$2"
  local sysctl_cnf="$3"

  cut -d\# -f1 ${sysctl_cnf} | grep "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}


function chk_sysctl {
  local flag="$1"
  local value="$2"

  sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}     


############################################

function chk_aslr {
#Ensure ASLR is enabled
  grep -i '^\s*kernel\.randomize_va_space\s*= \s*2\b'  $SYSCTL_CONF || return

}

function check_umask {
  cut -d\# -f1 /etc/init.d/functions | grep -q "umask[[:space:]]027" || return
}

function check_def_tgt {
  #Check that the default boot target is multi-user.target 
  local default_tgt
  default_tgt="$(systemctl get-default)"
  [[ "${default_tgt}" = "multi-user.target" ]] || return
}

function mta_local_only {
  # If port 25 is being listened on, check it is on the loopback address
  netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
  if [[ "$?" -eq 0 ]] ; then
    ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
    [[ "${ip}" = "127.0.0.1" ]] || return    
  fi
}

function ip6_router_advertisements_dis {
  # Check that IPv6 Router Advertisements are disabled
  # If ipv6 is disabled then we don't mind what IPv6 router advertisements are set to
  # If ipv6 is enabled then both settings should be set to zero
  chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
  chk_sysctl net.ipv6.conf.all.accept_ra 0 || return
  chk_sysctl net.ipv6.conf.default.accept_ra 0 || return
}
  
function ip6_redirect_accept_dis {
  # Check that IPv6 Redirect Acceptance is disabled
  # If ipv6 is disabled then we don't mind what IPv6 redirect acceptance is set to
  # If ipv6 is enabled then both settings should be set to zero
  chk_sysctl net.ipv6.conf.all.disable_ipv6 1 && return
  chk_sysctl net.ipv6.conf.all.accept_redirects 0 || return
  chk_sysctl net.ipv6.conf.default.accept_redirects 0 || return
}

function chk_file_exists {
  local file="$1"
  [[ -f "${file}" ]] || return
}

function chk_file_not_exists {
  local file="$1"
  [[ -f "${file}" ]] && return 1 || return 0
}
 
function chk_hosts_deny_content {
  # Check the hosts.deny file resembles ALL: ALL
  cut -d\# -f1 ${HOSTS_DENY} | grep -q "ALL[[:space:]]*:[[:space:]]*ALL" || return
}

function chk_cis_cnf { 
  local protocol="$1"
  local file="$2"
  grep -q "install[[:space:]]${protocol}[[:space:]]/bin/true" ${file} || return
} 

function chk_rsyslog_remote_host {
  # rsyslog should be configured to send logs to a remote host
  # grep output should resemble 
  # *.* @@loghost.example.com
  grep -q "^*.*[^I][^I]*@" ${RSYSLOG_CNF} || return
}



function rsyslog_perm {
#check rsyslog file creation permissions
grep -i "^\$FileCreateMode\s*0640" ${RSYSLOG_CONF} || return
}

function rsyslog_remote {

if grep -P -- '^\h*module\(load="imtcp"\)' ${RSYSLOG_CONF};then false;else true;fi || return
if grep -P -- '^\h*input\(type="imtcp" port="514"\)' ${RSYSLOG_CONF};then false;else true;fi || return
}

function journald_remote {
  if  systemctl is-enabled systemd-journal-remote.socket | grep -q masked;then true;else false;fi || return
}

function logfile_perm {

var=$(find /var/log/ -type f -perm /g+wx,o+rwx -exec ls -l "{}" +)
if test -z "$var" ;then true ;else false ;fi || return

 }


function audit_log_storage_size {
  # Check the max size of the audit log file is configured
  cut -d\# -f1 ${AUDITD_CNF} | egrep -q "max_log_file[[:space:]]|max_log_file=" || return
}


function dis_on_audit_log_full {
  # Check auditd.conf is configured to notify the admin and halt the system when audit logs are full
  cut -d\# -f2 ${AUDITD_CNF} | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'email' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'root' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'halt' || return
}

function max_audit_actions {
  # Check auditd.conf is configured to check max log files actions. 
  local arg="$1"
  local action="$2"
  cut -d\# -f2 ${AUDITD_CNF} | grep "\b${arg}\b" | cut -d= -f2 | tr -d '[[:space:]]' | grep  "\b${action}\b" || return
}

function audit_merge {
  #test if Audit rules have changed
 if augenrules --check | grep  -q "No change"; then
   return 0
    else
   retuen 1
  echo "Rules configuration differences between what is currently running and what is on disk could
cause unexpected problems or may give a false impression of compliance requirements."
 fi
}

function audit_procs_prior_2_auditd {
  # Check lines that start with linux have the audit=1 parameter set
  grep_grub="$(find /boot -type f -name 'grubenv' -exec grep -P 'kernelopts=([^#\n\r]+\h+)?(audit=1)' {} \;)"
  [[ ! -z "${grep_grub}" ]] || return
}

function audit_backlog_limits {
  # Check lines that start with linux have the audit=1 parameter set
  grep_grub="$(grubby --info=ALL | grep -Po "\baudit_backlog_limit=8192\b")"
  [[ ! -z "${grep_grub}" ]] || return
}


 #Extract the log file path from the auditd.conf
 log_file_path=$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)
 # Get the directory path of the log file
 directory_log=$(dirname "$log_file_path")

function audit_log_perm1 {
 #check log files are mode 0640 or less permissive. Find files in the directory and its subdirectories based on permission criteria
 if [ -n "$(find ${directory_log} -type f \( ! -perm 600 -a ! -perm 0400 -a ! -perm 0200 -a ! -perm 0000 -a ! -perm 0640 -a ! -perm 0440 -a ! -perm 0040 \) -exec stat -Lc "%n %#a" {} +)" ] ; then
   return  1
     else
   return  0
 fi
}

function audit_log_perm2 {
 #check user owner
 
  if [ -n "$(find ${directory_log} -type f ! -user root -exec stat -Lc "%n %U" {} +)" ] ; then
  return  1
    else
   return  0
 fi
}

function audit_log_perm3 {
 #check group owner
  if [ -n "$(find ${directory_log} -type f ! -group root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_log_perm4 {
 #check the audit log directory is 0750 or more restrictive 
  if [ -n "$(stat -Lc "%n %a" ${directory_log} | grep -Pv -- '^\h*\H+\h+([0,5,7][0,5]0)')" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_conf_perm1 {
 #check the audit log directory is 0750 or more restrictive 
 if find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) -exec stat -Lc "%n %a" {} + | grep -Pv -- '^\h*\H+\h*([0,2,4,6][0,4]0)\h*$' >> ./$LOGFILE ;then 
   return 1
    else 
   return 0
 fi
}

function audit_conf_perm2 {
#check auditd dir user owner
  if [ -n "$(find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}
  
function audit_conf_perm3 {
#check auditd dir group owner
  if [ -n "$(find ${AUDIT_DIR} -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec stat -Lc "%n %U" {} +)" ] ; then
   return  1
    else
   return  0
 fi
}

function audit_tools_perm {
 #check audit tools permissions
 if stat -c "%n %a" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
 if stat -c "%n %U" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+root\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
 if stat -c "%n %a %U %G" ${AUDIT_TOOLS} | grep -Pv -- '^\h*\H+\h+([0-7][0,1,4,5][0,1,4,5])\h+root\h+root\h*$' >> ./$LOGFILE ;then return 1; else return 0;fi
}

function audit_date_time {
  # Confirm that the time-change lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+stime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/localtime" || return
}

function audit_user_group {
  # Confirm that the identity lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/group" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/passwd" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/gshadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/shadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/security\/opasswd" || return
}

function audit_network_env {
  # Confirm that the system-locale lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b32" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue.net" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/hosts" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sysconfig\/network" || return
}

function audit_logins_logouts {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/faillog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/lastlog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/tallylog" || return
}

function audit_session_init {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/run\/utmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/wtmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/btmp" || return
}

function audit_sys_mac {
  # Confirm that the logins lines specified below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/selinux\/" || return
}

function audit_dac_perm_mod_events {
  # Confirm that perm_mod lines matching the patterns below do appear in the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function unsuc_unauth_acc_attempts {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}




function coll_priv_cmds {
  local priv_cmds
  priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
  for cmd in ${priv_cmds} ; do
    cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+privileged" | egrep "\-F[[:space:]]+path=${cmd}" \
    | egrep "\-F[[:space:]]+perm=x" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
    | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  done
}

function coll_suc_fs_mnts {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function coll_file_del_events {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

function coll_chg2_sysadm_scope {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+scope" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sudoers" || return

}

function coll_sysadm_actions {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+actions" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/sudo.log" || return

}

function kmod_lod_unlod {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/insmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/rmmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/modprobe" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-S[[:space:]]+delete_module" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+init_module" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

function audit_cfg_immut {
  # There should be a "-e 2" at the end of the audit.rules file
  cut -d\# -f1 ${AUDIT_RULES} | egrep -q "^-e[[:space:]]+2" || return
}

function logrotate_cfg {
  [[ -f "${LOGR_SYSLOG}" ]] || return

  local timestamp
  timestamp=$(date '+%Y%m%d_%H%M%S')
  local tmp_data="/tmp/logrotate.tmp.${timestamp}"
  local file_list="/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/cron"
  local line_num
  line_num=$(grep -n '{' "${LOGR_SYSLOG}" | cut -d: -f1)
  line_num=$((${line_num} - 1))
  head -${line_num} "${LOGR_SYSLOG}" > ${tmp_data}
  for file in ${file_list} ; do
    grep -q "${file}" ${tmp_data} || return
  done
  rm "${tmp_data}" 
}

function cron_auth_users {
 [[ ! -f ${CRON_DENY} ]] || return 
 check_root_owns "${CRON_ALLOW}"
 check_file_perms "${CRON_ALLOW}" 640 
}

function at_auth_users {
 [[ ! -f ${AT_DENY} ]] || return 
 check_root_owns "${AT_ALLOW}"
 check_file_perms "${AT_ALLOW}" 640 
}

function crypto_policy {
#ensure system-wide crypto policy is not over-ridden 
 local  crypto="$(grep -i '^\s*CRYPTO_POLICY=' /etc/sysconfig/sshd)"
[[ -z "${crypto}" ]] || return

}

function chk_param {
  local file="${1}" 
  local parameter="${2}" 
  local value="${3}" 
  [[ -z ${3} ]] && spacer="" || spacer="[[:space:]]"
  cut -d\# -f1 ${file} | egrep -q "^\s*${parameter}\b${spacer}${value}" || return
}

function  chk_parm_2 {
  local file="${1}"
  local argm="${2}"
  local value="${3}"
cut -d\# -f1 ${file}|tr -d '[[:space:]]'| grep "$argm=$value" || return
}

function chk_ssh_conf2 {
 local arg="${1}" 
 local value="${2}" 
 sshd -T -C user=root -C host="$(hostname)" -C addr="$(grep $(hostname) /etc/hosts | awk '{print $1}')" | grep -qi "${arg} ${value}" || return
}


#function ssh_maxauthtries {
#  local allowed_max="${1}"
 # local actual_value
  #actual_value=$(cut -d\# -f1 ${SSHD_CFG} | grep 'MaxAuthTries' | cut -d" " -f2)
  #[[ ${actual_value} -le ${allowed_max} ]] || return 
#}

#function ssh_user_group_access {
 # local allow_users
  #local allow_groups
  #local deny_users
  #local deny_users
  #allow_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowUsers" | cut -d" " -f2)"
  #allow_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowGroups" | cut -d" " -f2)"
  #deny_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyUsers" | cut -d" " -f2)"
  #deny_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyGroups" | cut -d" " -f2)"
  #[[ -n "${allow_users}" ]] || return
  #[[ -n "${allow_groups}" ]] || return
  #[[ -n "${deny_users}" ]] || return
  #[[ -n "${deny_groups}" ]] || return
#}


function pty_sudo {
 local  pty="$(grep -rPi '^\h*Defaults\h+([^#\n\r]+,)?use_pty(,\h*\h+\h*)*\h*(#.*)?$' ${SUDOERS})"
  [[ ! -z "${pty}" ]] || return
 }
 

function log_sudo {
 local  log="$(grep -Ei '^\s*Defaults\s+([^#;]+,\s*)?logfile\s*=\s*(")?[^#;]+(")?' ${SUDOERS})"
  [[ ! -z "${log}" ]] || return
 }
 
 
function escalation_sudo {
   local escal="$(grep -r "^[^#].*NOPASSWD" ${SUDOERS})"
    echo "Remove any line with occurrences of !authenticate tags in the file"
    echo $reauth_escal
    echo $reauth_escal  >> ./$LOGFILE
   [[  -z "${escal}" ]] || return
} 
   
function reauth_escalation_sudo {
  local reauth_escal="$( grep -r "^[^#].*\!authenticate"  ${SUDOERS})"
    echo "Remove any line with occurrences of !authenticate tags in the file" >> ./$LOGFILE
    echo $reauth_escal
    echo $reauth_escal >> ./$LOGFILE
    [[  -z "${reauth_escal}" ]] || return
}

function  auth_timeout_sudo {
 local timeout="$(grep -v '^#' ${SUDOERS} | grep -oE '\s*timestamp_timeout=\s*([0-9]+)' | cut -d'=' -f2)"
 local timeout2="$(sudo -V | grep "Authentication timestamp timeout:" | cut -d" " -f4 | cut -d "." -f1)"
 if [[ $timeout -gt 15 ]] || [[ $timeout2 -gt 5 ]]; then
   echo $timeout
     echo $timeout >> ./$LOGFILE
       return 1
     else
   return 0
 fi
}

function faillock_enabled {
  fail="$(authselect current | grep -- "- with-faillock")"
  fail2="$(grep pam_faillock.so /etc/pam.d/password-auth /etc/pam.d/system-auth)"
  nullok="$(authselect current | grep -- "- without-nullok")"
  [[ -n ${fail} || ${fail2} ]] || return
  [[ -n ${nullok} ]] || return 
}


function pass_hash {
 
 grep -E  '^\s*password\s+(\S+\s+)+pam_unix\.so\s+(\S+\s+)*sha512\s*(\S+\s*)*(\s+#.*)?$' ${SYSTEM_AUTH} ${PASS_AUTH} || return
#Note,expire all user passwords if the hash algorithm was not sha512 :
# awk -F: '( $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $1 !="nfsnobody" ) { print $1 }' /etc/passwd | xargs -n 1 chage -d 0
}

function pass_req_params {
  # verify the pam_pwquality.so params in /etc/pam.d/system-auth
    grep -P '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' ${SYSTEM_AUTH} ${PASS_AUTH} || return
   local pqw="$(grep pam_pwquality.so ${SYSTEM_AUTH} ${PASS_AUTH})"
   [[ ! -z ${pqw} ]] || return
 #if (( ${pam1} | grep -oP '\s*remember=\s*\K\d+')> 2 ));then false; else true;fi  || return
 grep -q '^\s*minlen\s*=\s*14'  ${PWQUAL_CNF} || return
 grep -q '^\s*minclass\s*=\s*4' ${PWQUAL_CNF} || return
 # grep -q 'dcredit = -1' ${PWQUAL_CNF} || return
 # grep -q 'ucredit = -1' ${PWQUAL_CNF} || return
 # grep -q 'ocredit = -1' ${PWQUAL_CNF} || return
 # grep -q 'lcredit = -1' ${PWQUAL_CNF} || return
   grep -q '^\s*retry\s*=\s*3' ${PWQUAL_CNF} || return
}

function failed_pass_lock {
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_deny.so' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_env.so' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_deny.so' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_faillock.so preauth silent' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_faillock.so authfail' || return
 egrep "auth[[:space:]]+required" ${SYSTEM_AUTH} | grep -q 'pam_faillock.so' || return
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_faillock.so preauth silent' || return
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_faillock.so authfail' || return
 egrep "auth[[:space:]]+required" ${PASS_AUTH} | grep -q 'pam_faillock.so' || return

 if grep -q "nullok" ${PASS_AUTH} ; then  false ; else true ;fi || return
 if grep -q "nullok" ${SYSTEM_AUTH}; then  false ; else true ;fi || return

}

function remember_passwd {
 grep -Pq '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' ${SYSTEM_AUTH} || return
 grep -Pq '^\s*password\s+(sufficient|requisite|required)\s+pam_unix\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password_auth || return
 grep -Pq '^\s*password\s+(requisite|required)\s+pam_pwhistory\.so\s+([^#]+\s+)*remember=([5-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth || return

}

function su_access {
  grep -E '^\s*auth\s+required\s+pam_wheel\.so\s+(\S+\s+)*use_uid\s+(\S+\s+)*group=\S+\s*(\S+\s*)*(\s+#.*)?$' ${PAM_SU}| grep sugroup || return
  if [ -z "$(getent group sugroup | cut -d: -f4)" ]; then true ;else false ;fi || return
}

function secure_acc {
  # Check that system account's password are disabled
 local users="$(awk -F: '/nologin/ {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="LK") {print $1}')"
 echo "Accounts that configured the shell as nologin but their password are not locked:  ${users}" >> ./$LOGFILE
 echo "Accounts that configured the shell as nologin but their password are not locked:  ${users}" 
 [[ -z "${users}" ]] || return
}

function root_def_grp {
  local gid1
  local gid2
  gid1="$(grep "^root:" "${PASSWD}" | cut -d: -f4)" 
  [[ "${gid1}" -eq 0 ]] || return
  gid2="$(id -g root)" 
  [[ "${gid2}" -eq 0 ]] || return
}

function def_umask_for_users {
  cut -d\#  -f1 "${BASHRC}" | egrep -q "umask[[:space:]]+027" || return


}

function umask2 {
   passing=""
   grep -Eiq '^\s*UMASK\s+(0[0-7][2-7]7|[0-7][2-7]7)\b' /etc/login.defs && grep -Eqi '^\s*USERGROUPS_ENAB\s*"?no"?\b' /etc/login.defs && grep -Eq '^\s*session\s+(optional|requisite|required)\s+pam_umask\.so\b' /etc/pam.d/common-session && passing=true
   grep -REiq '^\s*UMASK\s+\s*(0[0-7][2-7]7|[0-7][2-7]7|u=(r?|w?|x?)(r?|w?|x?)(r?|w?|x?),g=(r?x?|x?r?),o=)\b' /etc/profile* /etc/bashrc* && passing=true
   [ "$passing" = true ] || return

}

function chk_password_cnf {
   #check the values which may be changed by users manually

   grep_out1="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,5 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out2="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,4 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out3="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,6 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"
   grep_out4="$( grep -E ^[^:]+:[^\!*] ${SHADOW} | cut -d: -f1,7 | awk -F: '{if ($2 == "") print $1, "0"; else print $1, $2}' | cut -d' ' -f2)"


   #Password Expiration
   false_count1=$(echo $grep_out1 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 366 ]] || echo "false"; done | wc -l);echo $false_count1
   #minimum days between password changes:
   false_count2=$(echo $grep_out2 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 100 ]] || echo "false"; done | wc -l);echo $false_count2
   #expiration warning
   false_count3=$(echo $grep_out3 | xargs -n1 | while read num; do [[ $num -gt 6 && $num -lt 100 ]] || echo "false"; done | wc -l);echo $false_count3
   #inactive password lock:
   false_count4=$(echo $grep_out4 | xargs -n1 | while read num; do [[ $num -gt 0 && $num -lt 31 ]] || echo "false"; done | wc -l);echo $false_count4
  
  # Define the array with the values of false_counts
  false_counts=(false_count1 false_count2 false_count3 false_count4)

  # Loop through the array
  for count in "${false_counts[@]}"; do
    if [ "${!count}" -eq 0 ]; then
        true
    else
        false || return
    fi
  done

}

function inactive_usr_acs_locked {
  # After being inactive for a period of time the account should be disabled
  local days
  local inactive_threshold=30
  days="$(useradd -D | grep INACTIVE | cut -d= -f2)"
  [[ ${days} -ge ${inactive_threshold} ]] || return
}

function inactive_usr_password_disabled {
#Review list of users which INACTIVE PASSWORD LOCK feature is disabled for (value -1).
dis_users="$(awk -F: '/^[^#:]+:[^!\*:]*:[^:]*:[^:]*:[^:]*:[^:]*:(\s*|-1|3[1-9]|[4-9][0-9]|[1-9][0-9][0-9]+):[^:]*:[^:]*\s*$/ {print $1":"$7}' /etc/shadow)"
echo "Users with inactivity password lock disabled :  ${dis_users}" >> ./$LOGFILE
echo "Users with inactivity password lock disabled :  ${dis_users}" >> ./$LOGFILE_ERRORS
echo "Users with inactivity password lock disabled :  ${dis_users}"
[[ -z ${dis_users} ]] || return

}

function last_pass {
   #check last changed password date
   awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; \
   do change=$(date -d "$(chage --list $usr | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s); \
   if [[ "$change" -gt "$(date +%s)" ]]; then \
   echo "User: \"$usr\" last password change was \"$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\""; fi;done
   [[ -z ${1} ]] || return

#list the users need to chage their password
#for usr in $(cut -d: -f1 /etc/shadow); do [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr$usr:---$(chage --list $usr | grep '^Last password change' | cut -d: -f2)"; done
#chage --list 

}


function shell_tmout {
  #check shell time out
  grep -qxF 'readonly TMOUT=1800 ; export TMOUT' ${PROFILE_D} || return
}


function root_pass  {
  #check if root user has a password
  passwd -S root | grep -q "Password set\b" || return

}


function warning_banners {
  # Check that system login banners don't contain any OS information
  local motd
  local issue
  local issue_net
  motd="$(egrep '(\\v|\\r|\\m|\\s)' ${MOTD})"
  issue="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE})"
  issue_net="$(egrep '(\\v|\\r|\\m|\\s)' ${ISSUE_NET})"
  [[ -z "${motd}" ]] || return
  [[ -z "${issue}" ]] || return
  [[ -z "${issue_net}" ]] || return
}

function gnome_banner {
  # On a host aiming to meet CIS requirements GNOME is unlikely to be installed 
  # Thus the function says if the file exists then it should have these lines in it
  if [[ -f "${BANNER_MSG}" ]] ; then
    egrep '[org/gnome/login-screen]' ${BANNER_MSG} || return
    egrep 'banner-message-enable=true' ${BANNER_MSG} || return
    egrep 'banner-message-text=' ${BANNER_MSG} || return
  fi
}

function unowned_files {
  local uo_files
  uo_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  echo_red "The files are:\n$uo_files\n "
  echo_red "The files are:$uo_files\n " >> ./$LOGFILE
  [[ -z "${uo_files}" ]] || return
}
 

function ungrouped_files {
  local ug_files
  ug_files="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  echo_red "The files are:\n$ug_files\n "
  echo_red "The files are:\n$ug_files\n " >> ./$LOGFILE
  [[ -z "${ug_files}" ]] || return
}

function suid_exes {
  # For every suid exe on the host use the rpm cmd to verify that it should be suid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local suid_exes rpm rpm_out
  suid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for suid_exe in ${suid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}
 
function sgid_exes {
  # For every sgid exe on the host use the rpm cmd to verify that it should be sgid executable
  # If the rpm cmd returns no output then the rpm is as it was when it was installed so no prob
  local sgid_exes rpm rpm_out
  sgid_exes="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print)"
  for sgid_exe in ${sgid_exes}
  do
    rpm=$(rpm -qf $suid_exe)
    rpm_out="$(rpm -V --noconfig $rpm | grep $suid_exe)"
    [[ -z "${rpm_out}" ]] || return
  done
}

function passwd_field {
  local shadow_out
  shadow_out="$(awk -F: '($2 == "" ) { print $1 }' ${SHADOW})"
  echo_red "Results:\n$shadow_out \n " >> ./$LOGFILE
  [[ -z "${shadow_out}" ]] || return
}

function passwd_shadow {
  local shadowed
  shadowed="$(awk -F: '($2 != "x" ) { print $1 }' ${PASSWD})"
  echo_red "Results:\n$shadowed \n " >> ./$LOGFILE
  [[ -z "${shadowed}" ]] || return
}

  
function shadow_group {  
local output1="$(awk -F: '($1=="shadow") {print $NF}' ${PASSWD})"
local output2="$(awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' ${GROUP})" '($4==GID) {print $1}' ${PASSWD})"

  [[ -z "${output1}" && -z "${output2}" ]] || return

}


function nis_in_file {
  # Check for lines starting with + in the supplied file $1 
  # In /etc/{passwd,shadow,group} it used to be a marker to insert data from NIS 
  # There shouldn't be any entries like this
  local file="${1}"
  local grep_out
  grep_out="$(grep '^+:' ${file})"
  [[ -z "${grep_out}" ]] || return
}

function no_uid0_other_root {
  local grep_passwd
  grep_passwd="$(awk -F: '($3 == 0) { print $1 }' ${PASSWD})"
  [[ "${grep_passwd}" = "root" ]] || return  
}

function world_perm {
#find files with 777 permission
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002)"
  echo_red "These files have 777 permission:\n$dirs \n "
  echo_red "These files have 777 permission:\n$dirs \n " >> ./$LOGFILE
  [[ -z "${dirs}" ]] || return
 }


function sticky_wrld_dirs {
  dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \
\( -perm -0002 -a ! -perm -1000 \))"
  echo_red "Result:\n$dirs\n "
  echo_red "Result:\n$dirs\n " >> ./$LOGFILE
  [[ -z "${dirs}" ]] || return
}

function root_path_old {
  # There should not be an empty dir in $PATH
  local grep=/bin/grep
  local sed=/bin/sed
  path_grep="$(echo ${PATH} | ${grep} '::')"
  [[ -z "${path_grep}" ]] || return 

  # There should not be a trailing : on $PATH
  path_grep="$(echo ${PATH} | ${grep} :$)"
  [[ -z "${path_grep}" ]] || return 

  path_dirs="$(echo $PATH | ${sed} -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')"
  for dir in ${path_dirs} ; do
    # PATH should not contain .
    [[ "${dir}" != "." ]] || return

    #$dir should be a directory
    [[ -d "${dir}" ]] || return

    local ls_out
    ls_out="$(ls -ldH ${dir})" 
    if is_group_writable ${ls_out} ; then return 1 ; else return 0 ; fi
    if is_other_writable ${ls_out} ; then return 1 ; else return 0 ; fi


    # Directory should be owned by root
    dir_own="$(echo ${ls_out} | awk '{print $3}')"
    [[ "${dir_own}" = "root" ]] || return
  done
}

function root_path {
 local  RPCV="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
 echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
 echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
 for x in $(echo "$RPCV" | tr ":" " "); do
  if [ -d "$x" ]; then
  output="$( ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"}  substr($1,6,1) != "-" {print $9, "is group writable"}  substr($1,9,1) != "-" {print $9, "is world writable"}')"
    else
   echo "$x is not a directory"
  fi
   if  [[ ! -z ${output} ]]; then
   echo -e "\n $output "  >> ./$LOGFILE
   return 1
  else
   echo
  fi
 done
}



function is_group_readable {
  local ls_output="${1}"
  # 5th byte of ls output is the field for group readable
  [[ "${ls_output:4:1}" = "r" ]] || return
}

function is_group_writable {
  local ls_output="${1}"
  # 6th byte of ls output is the field for group writable
  [[ "${ls_output:5:1}" = "w" ]] || echo $?
}

function is_group_executable {
  local ls_output="${1}"
  # 7th byte of ls output is the field for group readable
  [[ "${ls_output:6:1}" = "r" ]] || return
}

function is_other_readable {
  local ls_output="${1}"
  # 8th byte of ls output is the field for other readable
  [[ "${ls_output:7:1}" = "r" ]] || return
}

function is_other_writable {
  local ls_output="${1}"
  # 9th byte of ls output is the field for other writable
  [[ "${ls_output:8:1}" = "w" ]] || return
}

function is_other_executable {
  local ls_output="${1}"
  # 10th byte of ls output is the field for other executable
  [[ "${ls_output:9:1}" = "x" ]] || return
}

function audit_sys_rpm {
  echo "It is important to confirm that packaged system files and directories are maintained with
the permissions they were intended to have from the OS vendor. " >  $LOGDIR/rpm_packages_permissions_$TIME.log
  rpm -Va --nomtime --nosize --nomd5 --nolinkto >>   $LOGDIR/rpm_packages_permissions_$TIME.log
}

function home_dir_perms {
local count=0
local dir
# filter out specific users and get their directories
dirs=$(awk -F: '($1!="root" && $1!="halt" && $1!="sync" && $1!="shutdown" && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/usr/bin/false") { print $6 }' $PASSWD)

# check  permissions
 for dir in $dirs; do
  local stat=$(stat -c "%a"  $dir | awk '{print substr($0, length-2, 3)}')
   if [ $stat -gt 750 ]; then
     count=$((count+1))
    echo -e "Results: $dir"
   fi
 done

#check sum of false and true counts
 if [ $count -gt 0 ]; then
   return 1
    else
   return 0
 fi
}


function dot_file_perms {

local count=0
local dir

dirs=$(awk -F: '($1!="root" && $1!="halt" && $1!="sync" && $1!="shutdown" && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/usr/bin/false") { print $6 }' $PASSWD)

# check  permissions
 
 for dir in ${dirs}/.[A-Za-z0-9]* ; do
  stat=$(stat -c '%#a' $dir)
   if [ $stat -gt 0755 ]; then
     count=$((count+1))
    echo -e "Results: $dir"
   fi
 done

#check sum of false and true counts
 if [ $count -gt 0 ]; then
   return 1
    else
   return 0
 fi
}

function dot_rhosts_files {
     # We don't want to see any ~/.forward files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.rhosts" && -f "${dir}/.rhosts" ]] ; then
      return 1 
    fi
  done 
 }

function groups_passwd {
  # all groups in /etc/passwd should be exist in /etc/group 
  for i in $(cut -s -d: -f4 ${PASSWD} | sort -u ); do
   grep -q -P "^.*?:[^:]*:$i:" ${GROUP}
   if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> ./$LOGFILE
    return 1
   fi
  done
}


function chk_home_dirs_exist {
  #Check that users home directory do all exist
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      return 1 
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function chk_home_dirs_owns {
  #Check that users home directory owner
  while read user uid dir ; do
    if [[ "${uid}" -ge 1000 && ! -d "${dir}" && "${user}" != "nfsnobody" ]] ; then
      local owner
      owner="$(stat -L -c "%U" "${dir}")"
      [[ "${owner}" = "${user}" ]] || return
    fi
  done < <(awk -F: '{ print $1 " " $3 " " $6 }' ${PASSWD})
}

function dot_netrc_perms {

local count=0
local dir

dirs=$(awk -F: '($1!="root" && $1!="halt" && $1!="sync" && $1!="shutdown" && $7!="/sbin/nologin" && $7!="/usr/sbin/nologin" && $7!="/bin/false" && $7!="/usr/bin/false") { print $6 }' $PASSWD)

# check  permissions

 for dir in ${dirs}/.netrc ; do
  stat=$(stat -c '%a' $dir)
   if [ $stat -gt 750 ]; then
     count=$((count+1))
    echo -e "Results: $dir"
   fi
 done

#check sum of false and true counts
 if [ $count -gt 0 ]; then
   return 1
    else
   return 0
 fi

}

function user_dot_netrc {
  # check existence of .netrc files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})"
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.netrc" && -f "${dir}/.netrc" ]] ; then
     echo -e "Failed: Please check  ${dir}/.netrc"    >> ./$LOGFILE
     echo -e "Failed: Please check  ${dir}/.netrc" 
     return 1
    fi
  done
}


function user_dot_forward {
  # We don't want to see any ~/.forward files
  local dirs
  dirs="$(cut -d: -f6 ${PASSWD})" 
  for dir in ${dirs} ; do
    [[ -d "${dir}" ]] || continue
    if [[ ! -h "${dir}/.forward" && -f "${dir}/.forward" ]] ; then
      return 1 
    fi
  done
}

function duplicate_uids {
  local num_of_uids
  local uniq_num_of_uids
  num_of_uids="$(cut -f3 -d":" ${PASSWD} | wc -l)"
  uniq_num_of_uids="$(cut -f3 -d":" ${PASSWD} | sort -n | uniq | wc -l)" 
  [[ "${num_of_uids}" -eq "${uniq_num_of_uids}" ]] || return
}

function duplicate_gids {
  local num_of_gids
  local uniq_num_of_gids
  num_of_gids="$(cut -f3 -d":" ${GROUP} | wc -l)"
  uniq_num_of_gids="$(cut -f3 -d":" ${GROUP} | sort -n | uniq | wc -l)" 
  [[ "${num_of_gids}" -eq "${uniq_num_of_gids}" ]] || return
}

function duplicate_usernames {
  local num_of_usernames
  local num_of_uniq_usernames
  num_of_usernames="$(cut -f1 -d":" ${PASSWD} | wc -l)"
  num_of_uniq_usernames="$(cut -f1 -d":" ${PASSWD} | sort | uniq | wc -l)" 
  [[ "${num_of_usernames}" -eq "${num_of_uniq_usernames}" ]] || return
}

function duplicate_groupnames {
  local num_of_groupnames
  local num_of_uniq_groupnames
  num_of_groupnames="$(cut -f1 -d":" ${GROUP} | wc -l)"
  num_of_uniq_groupnames="$(cut -f1 -d":" ${GROUP} | sort | uniq | wc -l)" 
  [[ "${num_of_groupnames}" -eq "${num_of_uniq_groupnames}" ]] || return
}


function wlan_iface_disabled {
  nmcli -c no -m multiline radio all |grep -v "\-HW" |grep -q enabled && return 1 || return 0
}

function chk_cryptopolicy_not_legacy {
  egrep -qi '^\s*LEGACY\s*(\s+#.*)?$' /etc/crypto-policies/config && return 1 || return 0
}

function chk_cryptopolicy_future_fips {
  egrep -qi '^\s*(FUTURE|FIPS)\s*(\s+#.*)?$' /etc/crypto-policies/config || return
}

function chk_owner_group {
  local file=$1
  local owner_group=$2
  stat -c '%U:%G' $1 |grep -q "$2" || return
}

function cockpit {
 systemctl is-active cockpit | grep -qe  "^inactive"
}



clear
  echo -e "\n\n IP Address : $IP_ADR"       > ./$LOGFILE
  echo -e "\n Host Name    : $(hostname)"  >> ./$LOGFILE
  echo -e "\n OS Version   : $OS_VERSION"  >> ./$LOGFILE
  echo -e "\n Date : $(date '+%Y.%m.%d')             Time: $(date '+%H:%M') "  >> ./$LOGFILE
  echo -e "\n State           Index           Defined Argument" >> ./$LOGFILE
  echo -e "================================================================" >> ./$LOGFILE

  echo -e "\n\n IP Address : $IP_ADR"       > ./$LOGFILE_ERRORS
  echo -e "\n Host Name    : $(hostname)"  >> ./$LOGFILE_ERRORS
  echo -e "\n OS Version   : $OS_VERSION"  >> ./$LOGFILE_ERRORS
  echo -e "\n Date : $(date '+%Y.%m.%d')             Time: $(date '+%H:%M') "  >> ./$LOGFILE_ERRORS
  echo -e "\n State           Index           Defined Argument" >> ./$LOGFILE_ERRORS
  echo -e "================================================================" >> ./$LOGFILE_ERRORS

  
  function checker {
    let TOTAL++
    func_name=$1
    shift
    args=$@
    printf "${func_name} ${args}: "
    ${func_name} ${args} >/dev/null 2>&1
    if [[ "$?" -eq 0 ]]; then
      let PASS++
      echo_green  [PASSED]
 
      echo_green "Passed          $func_name                          $args" >> ./$LOGFILE
      echo -e "------------------------------------------------------------" >> ./$LOGFILE
    else
      let FAILED++
      echo_red  [FAILED]
 
      echo_red   "Error on:       $func_name                          $args" >> ./$LOGFILE
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE
      echo_red   "Error on:       $func_name                          $args" >> ./$LOGFILE_ERRORS
      echo  -e "-----------------------------------------------------------" >> ./$LOGFILE_ERRORS
    fi
 
  }
  




 # checking Initial Setup
   echo_red "\n********** 1.Initial Setup **********"

  echo_bold "##### 1.1.1 Disable unused file systems"
   checker disable_fs squashfs
   checker disable_fs udf
   checker disable_fs cramfs
   checker disable_fs usb-storage
     
	 
 echo_bold "##### 1.1.22 Ensure sticky bit is set on all world-writable directories #####"
  checker sticky_bit
  
  echo_bold "##### 1.2.1 GPG keys are configured #####"
   checker gpg_key_installed
   
  echo_bold "##### 1.2.2,4 gpgcheck is globally activated #####"
   checker gpg_check
 
   ####### 1.4.1 AIDE Config ####
   ## AIDE
  
  
 echo_bold "##### 1.4.2 Ensure permissions on bootloader config are configured"
   checker check_grub_owns
   checker check_file_perms ${GRUB_CFG} 700
   checker check_file_perms ${GRUB_ENV} 600
  
  
  echo_bold "##### 1.4.3 Ensure authentication required for single user mode #####"
   checker single_user_mode
   
  echo_bold "##### 1.5.1 Ensure core dumps are restricted"
  checker service_disabled coredump
  checker chk_sysctl fs.suid_dumpable   0
  checker chk_param "fs.suid_dumpable=" 0 ${SYSCTL_CONF}
  checker chk_param " hard core" 0 ${SEC_LIMITS}
   
   
  echo_bold "1.5.2 Ensure XD/NX support is enabled "
  checker xd_nx

   
   echo_bold "##### 1.5.3 Ensure address space layout randomization (ASLR) is enabled #####"
    checker chk_sysctl kernel.randomize_va_space 2
    checker chk_aslr
		
   echo_bold " 1.5.4 Ensure prelink is not installed "
	checker rpm_not_installed prelink 

  
  echo_bold "##### 1.6.1.1 Ensure SELinux is installed #####"
   checker rpm_installed libselinux
   
  echo_bold "##### 1.6.1.2 Ensure SELinux is not disabled in bootloader configuration #####"
   checker verify_selinux_grubcfg
   
  echo_bold "##### 1.6.1.4 Ensure the SELinux mode is not disabled #####"
   checker verify_selinux_state

  echo_bold "##### 1.6.1.7 Ensure SETroubleshoot is not installed #####"
   checker rpm_not_installed setroubleshoot 
   
  echo_bold "##### 1.6.1.8 Ensure the MCS Translation Service (mcstrans) is not installed #####"
   checker rpm_not_installed mcstrans
   
      
  echo_bold "##### 1.7.1 - 3 Ensure banners are configured #####"
   checker warning_banners
  
  echo_bold "##### 1.7.4 - 6 Ensure banners have permissions set #####"
  
   for file in ${MOTD} ${ISSUE} ${ISSUE_NET} ; do
     checker check_root_owns "${file}"
     checker check_file_perms "${file}" 644 
   done
  
  echo_bold "##### 1.8.2 Ensure GDM login banner is configured #####"
checker rpm_not_installed gdm

  echo_bold "##### 1.9 Ensure updates, patches and sec software installed #####"
   checker yum_update

  
 
#checking Servicess Configuration
  echo_red "\n**********2.Services **********\n"

  echo_bold "##### 2.2.1 Ensure time sync is in use #####"
   checker rpm_installed chrony
   
  echo_bold "##### 2.2.1.2 Ensure chrony is configured #####"
   checker chrony_cfg
      
  echo_bold "##### 2.2.3 Ensure chrony is not run as the root user  #####"
   checker  chrony_user

  echo_bold "##### 2.2.2 Ensure X Window System not installed #####"
   checker rpm_not_installed xorg-x11-server-common

  echo_bold "##### 2.2.2-22 Ensure unused services not installed #####"
   checker rpm_not_installed autofs
   checker rpm_not_installed avahi
   checker rpm_not_installed cups
   checker rpm_not_installed dhcp
   checker rpm_not_installed bind
   checker rpm_not_installed vsftpd
   checker rpm_not_installed tftp-server
   checker rpm_not_installed cyrus-imapd
   checker rpm_not_installed dovecot
   checker rpm_not_installed ypserv
   checker rpm_not_installed snmpd
   checker rpm_not_installed nginx
   checker rpm_not_installed httpd
   checker rpm_not_installed samba
   checker rpm_not_installed squid
   checker rpm_not_installed net-snmp
   checker rpm_not_installed telnet-server 
   checker rpm_not_installed dnsmasq
   checker rpm_not_installed nfs-utils
   checker rpm_not_installed rpcbind
   checker rpm_not_installed rsyncd
   checker rpm_not_installed xinetd
   checker rpm_not_installed openldap-servers

   
  echo_bold "##### 2.2.15 Ensure mail transfer agent (mta) is configured for local-only mode #####"
   checker chk_mta

  echo_bold "##### 2.3.1 Ensure unused client services not installed #####"
   checker rpm_not_installed ftp
   checker rpm_not_installed telnet
   checker rpm_not_installed openldap-clients
   checker rpm_not_installed tftp
   checker rpm_not_installed ypbind
   checker rpm_not_installed talk
   checker rpm_not_installed rsh
   
   
 
 # Checking Network Configuration
  echo_red "\n********** Network Configuration **********\n"


  echo_bold "##### 3.1.1 Verify if IPv6 is disabled on the sys_ctl #####" 
   checker ipv6_disabled
   checker chk_network_config net.ipv6.conf.default.disable_ipv6=1
   checker chk_network_config net.ipv6.conf.all.disable_ipv6=1

   echo_bold " ##### check ip v6 configuration from kernel #####"
    if ipv6_disabled >/dev/null 2>&1 ; then
     echo "ip v6 is disabled"
    else
     checker chk_sysctl net.ipv6.conf.default.disable_ipv6 1
     checker chk_sysctl net.ipv6.conf.all.disable_ipv6 1
     checker chk_sysctl net.ipv6.conf.default.disable_ipv6 1
     checker chk_sysctl net.ipv6.conf.all.disable_ipv6 1
     checker chk_sysctl net.ipv6.conf.all.accept_source_route 0
     checker chk_sysctl net.ipv6.conf.default.accept_source_route 0
     checker chk_sysctl net.ipv6.conf.all.accept_redirects 0
     checker chk_sysctl net.ipv6.conf.default.accept_redirects 0
     checker chk_sysctl net.ipv6.conf.all.accept_ra 0
     checker chk_sysctl net.ipv6.conf.default.accept_ra 0
    fi

  
  echo_bold "##### 3.1.4 Ensure WLAN disabled #####" 
   checker wlan_iface_disabled
	 
  echo_bold "##### 3.2.1 Ensure IP forwarding disabled #####"
   checker  chk_network_config net.ipv4.ip_forward=0
   checker  chk_sysctl net.ipv4.ip_forward 0
   
   
 echo_bold "##### 3.2.2 Ensure packet redirect sending disabled #####"
   checker chk_network_config net.ipv4.conf.all.send_redirects=0
   checker chk_network_config net.ipv4.conf.default.send_redirects=0
   checker chk_sysctl net.ipv4.conf.all.send_redirects 0
   checker chk_sysctl net.ipv4.conf.default.send_redirects 0


 echo_bold "##### 3.3.1 Ensure source routed packets are not accepted  #####"
 
  echo_bold "Checking IPV4:"
  checker chk_network_config net.ipv4.conf.all.accept_source_route=0
  checker chk_network_config net.ipv4.conf.default.accept_source_route=0
  checker chk_sysctl net.ipv4.conf.all.accept_source_route 0
  checker chk_sysctl net.ipv4.conf.default.accept_source_route 0
  
 echo_bold "Checking IPV6:"
  checker chk_network_config net.ipv6.conf.all.accept_source_route 0
  checker chk_network_config net.ipv6.conf.default.accept_source_route 0
    
 echo_bold "##### 3.3.2 Ensure ICMP redirects not accepted #####"
  echo_bold "Checking IPV4:"
   checker chk_network_config net.ipv4.conf.all.accept_redirects=0
   checker chk_network_config net.ipv4.conf.default.accept_redirects=0
   checker chk_sysctl net.ipv4.conf.all.accept_redirects 0
   checker chk_sysctl net.ipv4.conf.default.accept_redirects 0

  echo_bold "Checking IPV6:"
   checker chk_network_config net.ipv6.conf.all.accept_redirects=0
   checker chk_network_config net.ipv6.conf.default.accept_redirects=0
 
  echo_bold "##### 3.3.3 Ensure secure ICMP redirects not accepted #####"
   checker chk_network_config net.ipv4.conf.all.secure_redirects=0
   checker chk_network_config net.ipv4.conf.default.secure_redirects=0
   checker chk_sysctl net.ipv4.conf.all.secure_redirects 0 
   checker chk_sysctl net.ipv4.conf.default.secure_redirects 0
 
   echo_bold "##### 3.3.4 Ensure suspicious packets are logged #####"
   checker chk_network_config net.ipv4.conf.all.log_martians=1
   checker chk_network_config net.ipv4.conf.default.log_martians=1
   checker chk_sysctl net.ipv4.conf.all.log_martians 1 
   checker chk_sysctl net.ipv4.conf.default.log_martians 1
   
  echo_bold "##### 3.3.5 Ensure broadcast ICMP requests ignored #####"
   checker chk_network_config net.ipv4.icmp_echo_ignore_broadcasts=1
   checker chk_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
 
 echo_bold "##### 3.3.6 Ensure bogus ICMP responses ignored #####"
   checker chk_network_config net.ipv4.icmp_ignore_bogus_error_responses=1
   checker chk_sysctl net.ipv4.icmp_ignore_bogus_error_responses 1
 
  echo_bold "##### 3.3.7 Ensure reverse path filtering enabled #####"
   checker chk_network_config net.ipv4.conf.all.rp_filter=1
   checker chk_network_config net.ipv4.conf.default.rp_filter=1
   checker chk_sysctl net.ipv4.conf.all.rp_filter 1
   checker chk_sysctl net.ipv4.conf.default.rp_filter 1
   

echo_bold "##### 3.3.8 Ensure TCP SYN Cookies enabled #####"
   checker chk_network_config net.ipv4.tcp_syncookies=1
   checker chk_sysctl net.ipv4.tcp_syncookies 1
   
 
 echo_bold "##### 3.3.9 Ensure IPv6 router advertisements are not accepted #####"
   checker chk_network_config net.ipv6.conf.all.accept_ra=0
   checker chk_network_config net.ipv6.conf.default.accept_ra=0
 
 
  echo_bold "##### 3.4.1 Ensure sctp kernel module is not available #####"
     checker disable_fs dccp
	 
  echo_bold "##### 3.4.2 Ensure dccp kernel module is not available #####"
     checker disable_fs sctp 
   
  echo_bold "##### 3.5.1.1 Ensure firwall service enabled and running #####" 
   checker check_svc_enabled firewalld
   
  echo_bold "##### 3.5.1.2 Ensure iptables service not enabled #####" 
   checker check_svc_not_enabled iptables-services
  
  echo_bold "##### 3.5.1.3 Ensure nftables service not enabled #####" 
  checker check_svc_not_enabled nftables
  
  echo_bold "##### 3.5.2.4 - 3.4.4.2.4 not checked since iptables and nftables disabled #####" 



# Checking Logging and Auditing
  echo_red "\n********** 4.Logging and Auditing **********\n"
   
    
  echo_bold "##### 4.1.1.1-2 Ensure auditd installed #####" 
   checker rpm_installed audit
   checker rpm_installed audit-libs
   checker check_svc_enabled auditd
    
  echo_bold "##### 4.1.1.3 Ensure auditing procs start prior auditd enabled #####" 
   checker audit_procs_prior_2_auditd
  
  echo_bold "##### 4.1.1.4 Ensure audit_backlog_limit is sufficient #####" 
   checker audit_backlog_limits
  
   echo_bold "##### 4.1.2 Ensure audit logs are not deleted - Set Max Log actions #####" 
    checker chk_parm_2 ${AUDITD_CNF} max_log_file 50
    checker chk_parm_2 ${AUDITD_CNF} max_log_file_action ROTATE
    checker chk_parm_2 ${AUDITD_CNF} space_left_action ROTATE
    checker chk_parm_2 ${AUDITD_CNF} admin_space_left_action ROTATE
    checker chk_parm_2 ${AUDITD_CNF} disk_full_action ROTATE
    checker chk_parm_2 ${AUDITD_CNF} disk_error_action SYSLOG
	
  echo_bold "##### 4.1.3.21 Ensure the running and on disk configuration is the same #####"
   checker audit_merge
   # augenrules --load (needs restart)
  

  echo_bold "##### 4.2.1.1 Ensure rsyslog installed #####" 
   checker rpm_installed rsyslog
  
  echo_bold "##### 4.2.1.2 Ensure rsyslog enabled #####" 
   checker check_svc_enabled rsyslog
  
  echo_bold "##### 4.2.1.3 Ensure rsyslog default file permissions are configured #####"
   checker rsyslog_perm

  echo_bold "##### 4.2.1.7	Ensure rsyslog is not configured to receive logs from a remote client #####"
   checker rsyslog_remote

  echo_bold "##### 4.2.1.4 Ensure logging is configured #####"
   checker chk_file_exists ${RSYSLOG_CNF}

  echo_bold "##### 4.2.2.1.4 Ensure journald is not configured to receive logs from a remote client #####"
   checker journald_remote
  
   echo_bold "##### 4.2.2.2 Ensure journald enabled #####" 
   checker chk_journald_enabled systemd-journald
  
  echo_bold "##### 4.2.2.3 Ensure journald configured to compress large logs #####"
   checker chk_param "${JOURNALD_CFG}" "Compress=yes"
  
  echo_bold "##### 4.2.2.4 Ensure journald configured to write logs to persist. disk #####"
   checker chk_param "${JOURNALD_CFG}" "Storage=persistent"

  echo_bold "##### 4.2.3 Ensure permissions on all logfiles are configured  #####"
    checker logfile_perm
 

echo_red "\n********** 5 Access, Authentication and Authorization **********\n"

echo_bold "##### 5.1.1 Ensure cron daemon is enabled #####"
  checker check_svc_enabled crond

  echo_bold "##### 5.1.2 - 7 Ensure perms for crontab files"
    for file in ${CRON_DIR} ${CRON_HOURLY} ${CRON_DAILY} ${CRON_WEEKLY} ${CRON_MONTHLY} ; do
    checker check_root_owns "${file}"
    checker check_file_perms "${file}" 700 
    done
    
    checker check_file_perms "${CRONTAB} " 600
    checker check_root_owns  "${CRONTAB} "

  echo_bold "##### 5.1.8  Ensure cron is restricted to authorized users"
   checker cron_auth_users

  echo_bold "##### 5.1.9 Ensure at is restricted to authorized users"
   checker at_auth_users
     
  echo_bold "##### 5.2.1 Ensure sudo is installd"
   checker rpm_installed sudo

  echo_bold "##### 5.2.2 Ensure sudo commands use pty"
   checker pty_sudo

  echo_bold "##### 5.2.3 Ensure sudo log file exists"
   checker log_sudo


 
 echo_bold "##### 5.3.1 Ensure permissions on sshd_config"
  checker check_file_perms "${SSHD_CFG}" 600 
  checker check_root_owns "${SSHD_CFG}"

 echo_bold "##### 5.3.2 Ensure permissions on SSH private host key files"
  for hostkey in /etc/ssh/ssh_host_*_key; do
    checker chk_owner_group "${hostkey}" "root:ssh_keys"
    checker check_file_perms "${hostkey}" 640
  done

 echo_bold "##### 5.3.3 Ensure permissions on SSH public host key files"
  for pubhostkey in /etc/ssh/ssh_host_*_key.pub; do
    checker chk_owner_group "${pubhostkey}" "root:root"
    checker check_file_perms "${pubhostkey}" 644
  done
  
 echo_bold "##### 5.3.5-20 Ensure SSH options are set properly"
  checker chk_param "${SSHD_CFG}" LogLevel VERBOSE
  checker chk_param "${SSHD_CFG}" UsePAM yes
  checker chk_param "${SSHD_CFG}" PermitRootLogin no
  checker chk_param "${SSHD_CFG}" HostbasedAuthentication no
  checker chk_param "${SSHD_CFG}" PermitEmptyPasswords no
  checker chk_param "${SSHD_CFG}" PermitUserEnvironment no
  checker chk_param "${SSHD_CFG}" IgnoreRhosts yes
  checker chk_param "${SSHD_CFG}" X11Forwarding no
  checker chk_param "${SSHD_CFG}" AllowTcpForwarding no
  checker chk_param "${SSHD_CFG}" Banner /etc/issue.net
  checker chk_param "${SSHD_CFG}" MaxAuthTries 4
  checker chk_param "${SSHD_CFG}" MaxStartups 10:30:60
  checker chk_param "${SSHD_CFG}" MaxSessions 10
  checker chk_param "${SSHD_CFG}" LoginGraceTime 60
  checker chk_param "${SSHD_CFG}" ClientAliveInterval 900
  checker chk_param "${SSHD_CFG}" ClientAliveCountMax 1
  checker chk_param "${SSHD_CFG}" Ciphers aes128-ctr,aes192-ctr,aes256-ctr
  checker chk_param "${SSHD_CFG}" MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
  checker chk_param "${SSHD_CFG}" KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchangesha256


 echo_bold "##### 5.3.5-21 Ensure SSH options are set properly - Second Check"
  checker chk_ssh_conf2  LogLevel VERBOSE
  checker chk_ssh_conf2  UsePAM yes
  checker chk_ssh_conf2  PermitRootLogin no
  checker chk_ssh_conf2  HostbasedAuthentication no
  checker chk_ssh_conf2  PermitEmptyPasswords no
  checker chk_ssh_conf2  PermitUserEnvironment no
  checker chk_ssh_conf2  IgnoreRhosts yes
  checker chk_ssh_conf2  X11Forwarding no
  checker chk_ssh_conf2  AllowTcpForwarding no
  checker chk_ssh_conf2  Banner /etc/issue.net
  checker chk_ssh_conf2  MaxAuthTries 4
  checker chk_ssh_conf2  MaxStartups 10:30:60
  checker chk_ssh_conf2  MaxSessions 10
  checker chk_ssh_conf2  LoginGraceTime 60
  checker chk_ssh_conf2  ClientAliveInterval 900
  checker chk_ssh_conf2  ClientAliveCountMax 1
  checker chk_ssh_conf2  ciphers aes128-ctr,aes192-ctr,aes256-ctr
  checker chk_ssh_conf2  macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
  checker chk_ssh_conf2  kexalgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchangesha256

  echo_bold "##### 5.3.14 Ensure system-wide crypto policy is not over-ridden"
    checker crypto_policy

echo_bold "##### 5.4.1 Ensure password creation req. configured"
   checker pass_req_params 
   checker chk_parm_2 "${PWQUAL_CNF}" minlen 14
   checker chk_parm_2 "${PWQUAL_CNF}" minclass 4
   checker chk_parm_2 "${PWQUAL_CNF}" retry 3
   checker chk_parm_2 "${PWQUAL_CNF}" maxsequence 3
   
   
 echo_bold "5.4.2 Ensure authselect includes with-faillock"
   checker faillock_enabled

   
 echo_bold "##### 5.4.3 Ensure password hashing algo is SH512"
   checker pass_hash


  echo_bold  "##### 5.4.2 Configure pam_faillock module"
  checker failed_pass_lock
  checker chk_param "${FAIL_CONF}"  "deny =" 5
  checker chk_param "${FAIL_CONF}" "unlock_time ="  900
  checker chk_param "${PWQUAL_CNF}"  "enforce_for_root" ""
  checker chk_param "${FAIL_CONF}"  "even_deny_root" ""
  checker chk_param "${FAIL_CONF}"  "silent" ""
  checker chk_param "${FAIL_CONF}"  "audit"  ""
  checker chk_param "${FAIL_CONF}"  "even_deny_root"  ""
  
  
  echo_bold "##### 5.4.4 Ensure password reuse is limited"
   checker remember_passwd 
   checker chk_parm_2 "${PWHISTORY_CNF}" remember 5

  
   echo_bold "##### 5.5.1.1 - 3 Ensure password config"
   checker chk_param "${LOGIN_DEFS}" PASS_MAX_DAYS 365
   checker chk_param "${LOGIN_DEFS}" PASS_MIN_DAYS 7
   checker chk_param "${LOGIN_DEFS}" PASS_WARN_AGE 7

  echo_bold "##### 5.5.1.1 - 3 Ensure curent users password configs are correct (check values)"
   checker chk_password_cnf

  echo_bold "##### 5.5.1.4 Ensure inactive password lock is 30 days or less" 
   checker inactive_usr_acs_locked

 echo_bold "##### 5.5.1.4 Review list of users which INACTIVE PASSWORD LOCK feature is disabled for (value -1)"
   checker inactive_usr_password_disabled
             inactive_usr_password_disabled

  echo_bold "##### 5.5.1.5 Ensure all users last password change date is in the past"
   checker last_pass

  echo_bold "##### 5.5.2 Ensure sys accounts are secured"
   checker secure_acc
  
  echo_bold "##### 5.5.3 Ensure default user shell timeout is 1800"
   checker shell_tmout 

  echo_bold "##### 5.5.4 Ensure default group for root is GID 0"
   checker root_def_grp

  echo_bold "##### 5.5.5 Ensure default user umask 027"
   checker  def_umask_for_users
   checker  umask2

  echo_bold "##### 5.5.6 Ensure root password is set"
   checker  root_pass 


  echo_bold "##### 5.7 Ensure access to su command restricted"
   checker su_access




 echo_red "\n********** 6 System Maintenance **********\n"


 echo_bold "##### 6.1.1 Audit system file permissions (from RPM package - Manual)) #####"
   checker audit_sys_rpm


  echo_bold "##### 6.1.2 - 9 Ensure perms on passwd(-), group(-) and shadow(-) files"
   checker check_file_perms "${PASSWD}" 644
   checker check_file_perms "${PASSWD2}" 644 
   checker check_file_perms "${GROUP}" 644 
   checker check_file_perms "${GROUP2}" 644 
   checker check_file_perms "${SHADOW}" 0
   checker check_file_perms "${SHADOW2}" 0
   checker check_file_perms "${GSHADOW}" 0 
   checker check_file_perms "${GSHADOW2}" 0 
  
   for file in ${PASSWD} ${PASSWD2} ${SHADOW} ${SHADOW2} ${GSHADOW} ${GSHADOW2} ${GROUP} ${GROUP2} ; do
     checker check_root_owns "${file}"
   done

  echo_bold "##### 6.1.10 Ensure no world writable files exist (777)"
    checker world_perm 
             world_perm     
  
  echo_bold "##### 6.1.11 Ensure no unowned files exist"
   checker unowned_files	
             unowned_files

  echo_bold "##### 6.1.12 Ensure no ungrouped files exist"
   checker ungrouped_files
	        ungrouped_files

   echo_bold "##### 6.1.13 Audit SUID executables"
   checker suid_exes
  
  echo_bold "##### 6.1.14 Audit SGID executables"
   checker sgid_exes
  
  
  echo_bold "##### 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords"
   checker passwd_shadow
  	   
  echo_bold "##### 6.2.2 Ensure password  fields are not empty"
   checker passwd_field

  echo_bold "##### 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group "
   checker groups_passwd

  echo_bold "##### 6.2.4 Ensure shadow group is empty "
   checker  shadow_group 

 echo_bold "##### 6.2.5 Ensure no duplicate UIDs exist"
   checker duplicate_uids

  echo_bold "##### 6.2.6 Ensure no duplicate GIDs"
   checker duplicate_gids

  echo_bold "##### 6.2.7 Ensure no duplicate user names"
   checker duplicate_usernames

  echo_bold "##### 6.2.8 Ensure no duplicate group names"
   checker duplicate_groupnames

  echo_bold "##### 6.2.9 Ensure root is the only UID 0 account"
   checker no_uid0_other_root

    echo_bold "##### 6.2.10 Ensure root PATH integrity"
   checker root_path
  
  echo_bold "##### 6.2.11 Ensure all users home dir exist"
   checker chk_home_dirs_exist

  echo_bold "##### 6.2.12 Ensure users own their home directories"
   checker chk_home_dirs_owns

  echo_bold "##### 6.2.13 Ensure users home directories permissions are 750 or more restrictive"
   checker home_dir_perms
           home_dir_perms

echo_bold "##### 6.2.14 Ensure users dot files are not group or world writable"
   checker dot_file_perms
             dot_file_perms
 echo_bold "##### 6.2.15 Ensure no local interactive user has .netrc files"
   checker user_dot_netrc
             user_dot_netrc
  echo_bold "##### 6.2.16 Ensure no users have .forward files "
   checker user_dot_forward             
             user_dot_forward

  echo_bold "##### 6.2.17 Ensure no users have .rhosts files "
   checker dot_rhosts_files
            dot_rhosts_files 

  echo_bold "other important actions"
   checker cockpit





echo_bold "\n Auditing Successfully Completed!"
echo_bold "\n You can find the reports in \e[36m$LOGFILE ,  $LOGFILE_ERRORS\e[0m files."

results
###################END###################



