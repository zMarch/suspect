Suspect is a simple bash script that attempts to detect common IoCs without relying on (much) signature based detection or known "bad" files.

It first looks at whether the kernel modules loaded are on disk and present in /proc/modules and kallsyms.

Afterwards, it attempts to check whether /etc/ld.so.preload exists, and if it's being hidden by a preloaded library. Preload kits are a bit out of fashion at the moment, but I felt obliged to include this check. It's accomplished by means of using the LD_PRELOAD environment variable to preload libc, which changes the order of loading preference back to close to how it should be.

Next, it does some process list stuff, primarly looking for running processes with deleted executables, and checking whether there's a lot of change in the processes. It also looks to see if any executables are compressed with UPX (I need to make this a bit more generic, instead of looking for the UPX! string, but eventually...)

It does some simple checks, like checking for executables in /tmp/, whether there's more than one root user, whether the extended attributes are set on files (commonly used by rootkits like SHv4), whether any daemon processes have spawned a shell, what processes have keepalive network connections, the number of keys in authorized_keys.

Suspect is not a replacement for comprehensive manual triage, and it won't find any php backdoors anywhere. 
