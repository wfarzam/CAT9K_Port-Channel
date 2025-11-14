from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
import re
from datetime import datetime
import time

# Credentials
USERNAME = "admin"
PASSWORDS = ["cisco", "cisco123"]

# File to store backed-up configs
BACKUP_FILE = "port_channel_backups.txt"

# Device list loader
def load_device_list(filename="cat9kdevices.txt"):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

# Utility: current timestamp
def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Backup running config for each interface
def backup_interface_config(conn, interfaces, ip):
    print(f"📥 Backing up config for interfaces on {ip}")
    with open(BACKUP_FILE, "a") as f:
        f.write(f"\n\n==== Backup from {ip} @ {timestamp()} ====\n")
        for intf in interfaces:
            output = conn.send_command(f"show run interface {intf}")
            f.write(f"\n--- {intf} ---\n{output}\n")

# Extract physical members of Po1 from 'show etherchannel summary'
def get_physical_members_of_po1(conn):
    output = conn.send_command("show etherchannel summary")
    members = []

    # Start parsing after detecting Port-channel
    lines = output.splitlines()
    parsing = False
    for line in lines:
        if "Port-channel" in line:
            parsing = True
            continue
        if parsing and re.search(r'[A-Za-z]+\d+/\d+(/\d+)?', line):
            # Match interfaces like Gi1/0/23, Hu1/0/49, Te1/1/1, etc.
            found = re.findall(r'([A-Za-z]+\d+/\d+(/\d+)?)', line)
            members.extend([i[0] for i in found])
        elif parsing and line.strip() == "":
            break
    print(f"🔎 Found Po1 physical members: {members}")
    return members

# Reset interface configs
def reset_interfaces(conn, interfaces):
    print(f"🧹 Clearing config with 'default interface' for: {interfaces}")
    cmds = [f"default interface {i}" for i in interfaces]
    return conn.send_config_set(cmds)

# Check if Po1 exists
def port_channel_exists(conn):
    output = conn.send_command("show etherchannel summary")
    return "Po1" in output

# Determine if switch is in stack mode
def is_stack_mode(conn):
    output = conn.send_command("show switch", use_textfsm=True)
    if isinstance(output, list) and len(output) > 1:
        print("🔗 Stack mode detected")
        return True
    print("🟢 Standalone mode detected")
    return False

# Check available interfaces for trunk config (excluding StackWise)
def get_available_interfaces(conn):
    candidates = [
        "FortyGigabitEthernet1/1/1",
        "FortyGigabitEthernet1/1/2",
        "HundredGigE1/0/49",
        "HundredGigE1/0/50",
        "HundredGigE2/0/49"
    ]
    available = []
    for intf in candidates:
        output = conn.send_command(f"show run interface {intf}")
        if "Invalid" in output or "not found" in output:
            continue
        if "stackwise-virtual link 1" in output:
            print(f"⚠️ {intf} is used for StackWise Virtual, skipping.")
            continue
        available.append(intf)
    return available

# Choose interface pair based on mode and availability
def select_physical_interfaces(available, is_stack):
    if "FortyGigabitEthernet1/1/1" in available and "FortyGigabitEthernet1/1/2" in available:
        return ["FortyGigabitEthernet1/1/1", "FortyGigabitEthernet1/1/2"]
    if is_stack and "HundredGigE1/0/49" in available and "HundredGigE2/0/49" in available:
        return ["HundredGigE1/0/49", "HundredGigE2/0/49"]
    if not is_stack and "HundredGigE1/0/49" in available and "HundredGigE1/0/50" in available:
        return ["HundredGigE1/0/49", "HundredGigE1/0/50"]
    return []

# Standard trunk + LACP interface config
def generate_interface_config(interface):
    return [
        f"interface {interface}",
        " switchport",
        " switchport trunk allowed vlan 101-110",
        " switchport mode trunk",
        " channel-group 1 mode active",
        " ip dhcp snooping trust",
        " mtu 9000",
        " no shutdown"
    ]

# Config for Port-channel 1
PORT_CHANNEL_CONFIG = [
    "interface Port-channel1",
    " switchport",
    " switchport trunk allowed vlan 101-110",
    " switchport mode trunk",
    " ip dhcp snooping trust",
    " mtu 9000",
    " no shutdown"
]

# Send full config to selected interfaces
def push_config(conn, interfaces):
    config = ["system mtu 9000"]
    for intf in interfaces:
        config.extend(generate_interface_config(intf))
    config.extend(PORT_CHANNEL_CONFIG)
    print(f"📦 Applying config to: {interfaces} + Port-channel1")
    conn.send_config_set(config)
    conn.save_config()
    print("💾 Config saved to startup")

# Process each switch
def process_device(ip):
    for pwd in PASSWORDS:
        device = {
            "device_type": "cisco_ios",
            "host": ip,
            "username": USERNAME,
            "password": pwd,
        }
        try:
            print(f"\n🔌 Connecting to {ip}...")
            conn = ConnectHandler(**device)
            print(f"✅ Logged in to {ip}")

            if port_channel_exists(conn):
                po1_members = get_physical_members_of_po1(conn)
                to_backup = ["Port-channel1"] + po1_members
                backup_interface_config(conn, to_backup, ip)
                reset_interfaces(conn, to_backup)

            stack = is_stack_mode(conn)
            available = get_available_interfaces(conn)
            selected = select_physical_interfaces(available, stack)

            if not selected:
                print(f"❌ No valid interface pair for config on {ip}")
                conn.disconnect()
                return

            push_config(conn, selected)
            conn.disconnect()
            return

        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
            print(f"❌ Login failed for {ip} with '{pwd}': {e}")
            continue
        except Exception as e:
            print(f"❌ Error on {ip}: {e}")
            continue

    print(f"🚫 All login attempts failed for {ip}")

# Main entry point
def main():
    devices = load_device_list()
    for ip in devices:
        process_device(ip)
        print("=" * 60)
        time.sleep(1)

if __name__ == "__main__":
    main()
