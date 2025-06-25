# Goal

Shim api to handle `fence_redfish` calls.

# Requirements

    $ sudo dnf install python3-cryptography.x86_64 fence-agents-redfish.x86_64

# Usage

Run the server:

    $ python3 server.py

Run the fence agent:

    $ fence_redfish -a 127.0.0.1 --ipport 8443 -l foo -p bar --ssl-insecure -o off ; echo $?
    Success: Already OFF
    $ fence_redfish -a 127.0.0.1 --ipport 8443 -l foo -p bar --ssl-insecure -o on ; echo $?
    Success: Powered ON
    $ fence_redfish -a 127.0.0.1 --ipport 8443 -l foo -p bar --ssl-insecure -o reboot ; echo $?
    Success: Rebooted

If the returned power state is not immediately what the client expects, then the client will retry.
If you power off a system, and `Systems.Status.State` is not `Disabled`, then the client will retry until the state is `Disabled`.
