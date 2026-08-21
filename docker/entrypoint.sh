#!/usr/bin/env bash
# Boots a system D-Bus and firewalld inside the container (no systemd), seeds a small
# test configuration, then execs the requested command.
set -euo pipefail

mkdir -p /run/dbus
if [ ! -S /run/dbus/system_bus_socket ]; then
    dbus-daemon --system --fork
fi

# The integration suite requires both this marker and Docker's container
# identity before any real-firewalld test may run.
export FWDECK_REAL_FIREWALLD_TEST=1
install -m 0644 /dev/null /run/fwdeck-disposable-firewalld

# Reviewed traffic-observation seeds. These files mirror the Phase 0 golden
# service fixture and are loaded only by this disposable container daemon.
install -d -m 0755 /etc/firewalld/services
cat >/etc/firewalld/services/metrics.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>FWDeck Metrics Seed</short>
  <description>Disposable FWDeck semantic observation child service.</description>
  <port port="9100" protocol="tcp"/>
</service>
EOF
cat >/etc/firewalld/services/admin-stack.xml <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>FWDeck Admin Stack Seed</short>
  <description>Disposable FWDeck semantic observation root service.</description>
  <port port="8443" protocol="tcp"/>
  <protocol value="gre"/>
  <source-port port="1024-65535" protocol="tcp"/>
  <module name="nf_conntrack_ftp"/>
  <destination ipv4="239.1.1.0/24" ipv6="ff02::fb"/>
  <include service="metrics"/>
  <helper name="ftp"/>
</service>
EOF

if ! firewall-cmd --state >/dev/null 2>&1; then
    /usr/sbin/firewalld --nofork --nopid &
    for _ in $(seq 1 50); do
        firewall-cmd --state >/dev/null 2>&1 && break
        sleep 0.2
    done
fi

if firewall-cmd --state >/dev/null 2>&1; then
    # Permanent-side seeds first (the reload below would wipe runtime seeds):
    # an ipset and one permanent service, then reload to materialize them.
    firewall-cmd -q --permanent --new-ipset=blocklist --type=hash:ip 2>/dev/null || true
    firewall-cmd -q --permanent --ipset=blocklist --add-entry=203.0.113.9 2>/dev/null || true
    firewall-cmd -q --permanent --add-service=https || true
    firewall-cmd -q --permanent --new-zone=fwdeck-observe 2>/dev/null || true
    firewall-cmd -q --permanent --zone=fwdeck-observe --add-service=ssh || true
    firewall-cmd -q --permanent --new-zone=fwdeck-service 2>/dev/null || true
    firewall-cmd -q --permanent --zone=fwdeck-service --add-service=admin-stack
    if firewall-cmd -q --permanent --zone=fwdeck-observe --set-ingress-priority=-10 2>/dev/null; then
        firewall-cmd -q --permanent --zone=fwdeck-observe --set-egress-priority=10
    fi
    firewall-cmd -q --permanent --direct --add-rule ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT || true
    firewall-cmd -q --reload || true

    # Runtime-only seeds so the runtime/permanent drift indicator ("different")
    # is testable, and every view has real data.
    firewall-cmd -q --add-service=http || true
    firewall-cmd -q --add-service=https || true
    firewall-cmd -q --zone=fwdeck-observe --add-service=https || true
    firewall-cmd -q --add-port=8080/tcp || true
    firewall-cmd -q --zone=public --add-interface=eth0 || true
    firewall-cmd -q --zone=home --add-source=192.168.1.0/24 || true
    firewall-cmd -q --add-forward-port=port=8080:proto=tcp:toport=80:toaddr=10.0.0.5 || true
    firewall-cmd -q --add-rich-rule='rule family="ipv4" source address="203.0.113.0/24" reject' || true
    # FWDECK_DEMO_LOGS=1 injects sample netfilter lines into the kernel ring so
    # the Logs view has data. Needed because container-VM kernels (OrbStack /
    # Docker Desktop) cannot emit real netfilter logs from a container netns
    # (no nf_log_all_netns knob / no nf_log_syslog module). Real hosts work.
    if [ "${FWDECK_DEMO_LOGS:-0}" = "1" ] && [ -w /dev/kmsg ]; then
        echo '<4>FINAL_REJECT: IN=eth0 OUT= MAC=aa SRC=203.0.113.7 DST=172.18.0.2 LEN=60 PROTO=TCP SPT=51000 DPT=23 SYN' > /dev/kmsg
        echo '<4>filter_IN_public_DROP: IN=eth0 OUT= SRC=198.51.100.9 DST=172.18.0.2 PROTO=UDP SPT=999 DPT=161' > /dev/kmsg
        echo '<4>filter_IN_public_ACCEPT: IN=eth0 OUT= SRC=192.0.2.1 DST=172.18.0.2 PROTO=TCP DPT=22' > /dev/kmsg
    fi
    echo "firewalld: $(firewall-cmd --state)"
else
    echo "warning: firewalld failed to start; is the container privileged?" >&2
fi

exec "$@"
