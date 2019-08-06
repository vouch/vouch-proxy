# Startups Scripts

If you are running Vouch Proxy on a linux system, instead of docker, you may want to automatically start Vouch Proxy.

:bangbang: Please note, we highly recommend running Vouch Proxy as a **regular user**.  Vouch Proxy listens on port 9090 and doesn't require ANY root privileges.  **Please DO NOT run Vouch as root**.

All provided scripts assume that the compiled Vouch Proxy binary `vouch-proxy` has been installed in `/opt/vouch-proxy` with the executable flag set and owned by `vouch-proxy` user (that has also been created)
 
## Systemd

```
cp startup/systemd/vouch-proxy.service /etc/systemd/system/vouch-proxy.service
systemctl enable vouch-proxy.service
systemctl start vouch-proxy.service
```