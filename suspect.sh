#!/bin/bash
declare libc
declare proca
#we use strings and readlink; can't remember if they are standard


banner() {
echo "==== Compromise Triage Script ===="
echo "Because signatures are bad, m'kay."
echo "=================================="
}

modulecheck() {
#god bless you, NSA's autorootkit
declare kernelhashes
declare -a modulea
declare -i r1
declare moduleb

echo "[*] Comparing kallsyms and /proc/modules."
kernelhashes=$(cat /proc/kallsyms | grep '\[' | awk '{ print substr($4,2,length($4)-2) }' | sort -u | tr --delete "\n" | sha256sum)
if echo $kernelhashes | grep -q `cat /proc/modules | awk '{print $1}' | sort -u | tr --delete "\n" | sha256sum`; then
	echo "[*] kallsyms and /proc/modules match. Okay!"
else
	echo "[!] kallsyms and /proc/modules DO NOT MATCH. Possible compromise."
fi
echo "[*] Checking if any modules are missing from disk."
#i should really turn the below into a function
moduleb=$(lsmod | cut -d " " -f 1 | tail -n +2)
IFS=' ' read -r -a modulea <<< $moduleb
for i in "${modulea[@]}"; do
	modinfo -F filename $i >/dev/null 2>&1
	r1=$?
	if [ $r1 -eq "1" ]; then
		echo "[!] Module $i can't be found on disk!"
		moduleb="qqqqqqq"
	fi
done
if echo $moduleb | grep -vq "qqqqqqq"; then
	echo "[*] All modules found on disk."
fi
}

preloadcheck() {
declare -i r1
declare -i r2
echo "[*] Investigating ld.so.preload file."
cat /etc/ld.so.preload 2>/dev/null
r1=$?
LD_PRELOAD=$libc cat /etc/ld.so.preload 2>/dev/null
r2=$?
if [ $r1 -ne $r2 ]; then
	echo "[!] /etc/ld.so.preload is being hidden!"
	else
		echo "[*] /etc/ld.so.preload is either non-existent or not hidden."
	if [ -f "/etc/ld.so.preload" ]; then
		echo "[*] Contents of ld.so.preload, review manually."
	       cat /etc/ld.so.preload
       fi
fi       
}

missingproc() {
declare -a procs
echo "[*] Checking for processes with deleted executables."
IFS=' ' read -r -a procs <<< $proca
for i in "${procs[@]}"; do
	if readlink /proc/$i/exe | grep -q deleted; then
		echo "[!] PID $i is missing its executable."
		ps -p$i --no-header -o "%a"
	fi
done
}

changingproc() {
declare procb
declare procc
declare -i procn
echo "[*] Getting process lists."
procb=$(ps -wweo "%p")
echo "[*] Sleeping for three seconds."
sleep 3
procc=$(ps -wweo "%p")
procn=$(echo $proca $procb $procc | tr ' ' '\n' | sort | uniq -u | wc -l)
if [ $procn -gt "15" ]; then
	echo "[!] Seems like a lot of processes spawning."
	echo "[!] Investigate manually..."
else
	echo "[*] There's not a whole lot of process changes."
	echo "[*] That doesn't mean there are no malicious processes."
fi
}

oddexecs() {
echo "[*] Finding weird executables in places they shouldn't be."
find /tmp/ -executable -type f 2>/dev/null
find /var/tmp -executable -type f 2>/dev/null
}

extraroot() {
declare -i roots
echo "[*] Checking the number of root users in /etc/passwd."
roots=$(cat /etc/passwd | cut -d ":" -f3 | grep --color=never "^0$" | uniq -u | wc -l)
if [ $roots -gt 1 ]; then
	echo "[*] You've got more than one user with uid 0."
	echo "[*] Investigate manually."
else
	echo "[*] Just one root user, okay!"

fi
}

chattrsia() {
declare attribs
echo "[*] Checking for extended attributes on system binaries..."
attribs=$(lsattr -a /usr/bin/ /bin/ /sbin/ /usr/sbin/ 2>/dev/null | grep "\-ia\|^s")
if echo $attribs | grep -q "\-\-"; then
	echo "[!] Extended attributes set on some files!"
	echo $attribs
else
	echo "[*] No extended attributes set."
fi
}

daemonshells() {
echo "[*] Looking for any daemon processes running a shell..."
ps -weFH | grep -v $(getent passwd | grep sh$ | cut -d ":" -f 1 | tr '\n' '|' | sed s'/|/\\\|/g'  | sed s'/..$//') | grep sh
}

networks() {
declare -a neta
declare netb
echo "[*] Getting a list of programs with keepalive connections."
echo "[*] Investigate manually."
netb=$(ss -taoup | grep keepalive | cut -d \" -f 3 | cut -d "=" -f 2 | cut -d "," -f 1 | sort | uniq)
IFS=' ' read -r -a neta <<< $netb
for i in "${neta[@]}"; do
	ps --no-header -p$i -wwo "%p %u %a"
done
}

authkeys() {
declare -a homedira
declare homedir
echo "[*] Checking the authorized_keys for each user."
homedir=$(getent passwd | grep sh$ | cut -d ":" -f 6)
IFS=' ' read -r -a homedira <<< $homedir
for i in "${homedira[@]}";do
	if [ -f "$i/.ssh/authorized_keys" ]; then
		echo "[*] There's `cat "$i/.ssh/authorized_keys" | wc -l` keys in $i/.ssh/authorized_keys"
	fi
done
}

upxcheck() {
declare -a procs
echo "[*] Checking for UPX'd binaries."
IFS=' ' read -r -a procs <<< $proca
for i in "${procs[@]}"; do
	if [ $(cat "/proc/$i/exe" 2>/dev/null | tr -dc '[:print:]' | grep -oi "UPX\!" | wc -l) -gt 1 ] ; then
		echo "[*] Proc $i is compressed with UPX!"
		ps --no-header -p$i -wwo "%p %u %a"
	fi
done
}

modified() {
echo "[*] Checking for recent files in system locations..."
echo "[*] This may produce a lot of output."
find /usr/bin/ /bin/ /lib/ /lib64/ /usr/lib/ /usr/lib64/ /etc/ /tmp/ -mtime -7 -type f 2>/dev/null
}

main() {
banner
echo "[*] Checking for suspicious behaviour."
echo "[*] This is not a replacement for a manual audit."
proca=$(ps -wweo "%p")
libc=ldd $(which id) | awk -F " " '{print $3}' | grep --color=never libc
modulecheck
missingproc
changingproc
oddexecs
extraroot
chattrsia
daemonshells
networks
authkeys
upxcheck
modified
}

main
