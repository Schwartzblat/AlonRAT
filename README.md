## My personal RAT (Remote Administration Tool) project

### Currently under development.

#### The current architecture is:
1. "Innocent" service that serves at a stupid injector (currently using basic dll injection because it doesn't really matter, every normal injection method is already known by AntiViruses).
2. The service injects the AlonRAT dll into a system process like `svchost.exe` or `winlogon.exe`, I haven't decided yet.
3. The tool queries the c&c server in intervals.
4. Both PEs will be hardly obfuscated by string obfuscator and winapi obfuscator (using the peb and dynamic loading).



## Current features:
1. Run command as system.
2. Run command as user using token impersonation. 

## Some cool ideas I will probably implement:
1. Encryption of the on-disk dll.
2. Encrypt the code that access the peb.
3. Inject to more processes to make this tool harded to uninstall.
4. Anti Wireshark like tools.
5. Anti debugging.
6. Anti virust toal (sleeps, get a key from the server to enter a suspicious flow).


## Contribution

I am making this tools as a personal project so I will develop it on my own.
If you a cool idea for a feature or suggestions for improvements, you can open an issue and if it's cool I will do it.


## Purpose
Bla bla bla this repo is for educational purposes only, don't do shitty things with it.


