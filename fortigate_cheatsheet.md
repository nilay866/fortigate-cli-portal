# FortiGate 100% CLI Operations & Troubleshooting Manual (Zero GUI Required)

This manual is engineered for network engineers who operate **exclusively through the FortiGate CLI / SSH terminal**. Every operation—from policy creation, rule reordering, viewing traffic hit counters, reading logs, and debugging drops—is documented with 100% pure CLI commands.

---

## 0. FortiOS CLI Core Architecture (The 4 Master Verbs)

Every CLI command in FortiOS starts with one of four verbs:

| Verb | Purpose | Example |
|---|---|---|
| `get` | Display current runtime state, operational status, hardware readings, and routing tables | `get system status`<br>`get router info routing-table all` |
| `show` | Display stored configuration file (filters out default hidden parameters) | `show firewall policy 1`<br>`show firewall address "H_192.168.1.100"` |
| `diagnose` | Real-time debugging, packet sniffing, hardware diagnostics, and daemon monitoring | `diagnose debug flow ...`<br>`diagnose sniffer packet any 'icmp' 4 0 l` |
| `execute` | Run an operational action, trigger backups, restart services, or view log streams | `execute ping 8.8.8.8`<br>`execute log display`<br>`execute backup config ...` |

### Configuration Navigation Hierarchy
```fortios
config <path>               # 1. Enter configuration subtree (e.g., config firewall policy)
  edit <id_or_name>         # 2. Enter specific object. Use 'edit 0' to auto-assign next free ID
    set <parameter> <value> # 3. Modify a value
    unset <parameter>       # 4. Remove a value / revert parameter to factory default
  next                      # 5. Save this object and move to the next entry
end                         # 6. COMMIT ALL CHANGES TO MEMORY IMMEDIATELY
abort                       # Discard uncommitted changes and exit without saving
```

---

## 0.1 Essential CLI Policy Operations (No Web GUI Needed)

### 1. View / Search Policies in CLI
```fortios
# View all configured firewall policies
show firewall policy

# View one specific policy by ID number
show firewall policy <policy_id>

# View full configuration including all hidden default parameters
show full-configuration firewall policy <policy_id>
```

### 2. Move / Reorder Policies in CLI (Crucial: Rules are Top-to-Bottom!)
In FortiOS, policies are evaluated strictly from top to bottom. If rule 10 catches traffic before rule 5, rule 10 will take effect. You reorder rules directly from CLI:

```fortios
config firewall policy
  # Move policy 25 BEFORE policy 5 (places rule 25 higher in the list)
  move 25 before 5

  # Move policy 12 AFTER policy 3 (places rule 12 lower in the list)
  move 12 after 3
end
```

### 3. Check Policy Hit Counts & Byte Counters via CLI
To verify if traffic is actually hitting a specific firewall policy:

```fortios
# Display packet and byte counters for all IPv4 policies
diagnose firewall iprope show 100004 0

# Check hit counter for a specific policy ID (e.g., Policy ID 5)
diagnose firewall iprope show 100004 5
```
*Output will display `packets=<num>` and `bytes=<num>`. If packets=0, traffic is not matching this policy.*

### 4. Enable or Disable a Policy Without Deleting It
```fortios
config firewall policy
  edit <policy_id>
    set status disable        # Temporarily disables the rule
    # set status enable       # Re-enables the rule
  next
end
```

### 5. Check Where an Object is Used Before Deleting It
If you try to delete an address or service object that is currently used in a policy, FortiOS blocks you with: `object is used by another entry`. Use this CLI command to find the dependency:

```fortios
# Check where an address object is referenced
diagnose sys checkused firewall.address.name "<object_name>"

# Check where an address group is referenced
diagnose sys checkused firewall.addrgrp.name "<group_name>"

# Check where a service object is referenced
diagnose sys checkused firewall.service.custom.name "<service_name>"
```

### 6. Read and Filter Traffic Logs Directly in CLI (Zero GUI)
You do NOT need the web interface to read logs. FortiOS has a built-in CLI log engine:

```fortios
# Step 1: Set log category (0 = Traffic logs, 1 = Event logs, 2 = Security logs)
execute log filter category 0

# Step 2: Set filters (filter by source IP, destination IP, or port)
execute log filter field srcip <client_ip>
execute log filter field dstip <server_ip>
execute log filter field dstport <port_number>

# Step 3: Set number of log lines to view (e.g., last 30 entries)
execute log filter view-lines 30

# Step 4: Display the filtered logs
execute log display

# Step 5: Reset log filter back to default when done
execute log filter reset
```

---

## 0.2 The 5-Step FortiOS CLI Prerequisite Workflow ("Find or Make First")

In FortiOS, **a firewall policy is a top-level assembler**. It cannot create objects on the fly. If you try to run:
```fortios
set srcaddr "H_192.168.1.100"
```
and the object `"H_192.168.1.100"` does not already exist in memory, the FortiOS CLI will immediately reject your command with:
`node_check_object fail! for srcaddr H_192.168.1.100`  
`Command fail. Return code -61`

To prevent all parsing and node errors, follow the **Bottom-Up CLI Workflow**:

```
[ STEP 1: DISCOVER ] ──> Check if interfaces, IP objects, & services already exist
         │
[ STEP 2: PREREQUISITES ] ──> Create missing Address Objects, Services, VIPs, or Pools
         │
[ STEP 3: ASSEMBLE ] ──> Build Firewall Policy / Route referencing verified objects
         │
[ STEP 4: REORDER ] ──> Find auto-assigned policy ID & move above broad/deny rules
         │
[ STEP 5: VERIFY ] ──> Validate hit counters (iprope), session table, & CLI logs
```

---

### Complete Walkthrough: Creating a Firewall Policy from Scratch (Zero GUI)

#### STEP 1: Discover & Find Existing Objects (Run These First!)
Before typing `config firewall policy`, verify what interfaces and objects are already available:

```fortios
# 1. Check physical and VLAN interface names (ensure ports are UP):
get system interface physical
show system interface ?

# 2. Check if your client/source address object already exists:
get firewall address | grep -i "<client_ip>"
show firewall address "H_<client_ip>"

# 3. Check if your destination server address object already exists:
get firewall address | grep -i "<server_ip>"
show firewall address "H_<server_ip>"

# 4. Check if the required service/port already exists:
get firewall service custom | grep -i "<port>"
show firewall service custom "SVC_Custom_<port>"

# 5. Check active routing table to verify egress port to destination:
get router info routing-table details <server_ip>
```

#### STEP 2: Create Any Missing Prerequisites
If the objects or services were NOT found in Step 1, create them now:

```fortios
# 1. Create Source Address Object (if missing):
config firewall address
  edit "H_<client_ip>"
    set subnet <client_ip> 255.255.255.255
    set comment "Client workstation"
  next
end

# 2. Create Destination Address Object (if missing):
config firewall address
  edit "H_<server_ip>"
    set subnet <server_ip> 255.255.255.255
    set comment "Destination server"
  next
end

# 3. Create Custom Service Port (if not a standard port like HTTP/HTTPS):
config firewall service custom
  edit "SVC_Custom_<port>"
    set tcp-portrange <port>
    set comment "Application TCP port"
  next
end
```

#### STEP 3: Assemble the Firewall Policy
Now that all prerequisites are verified, construct the policy without any parse errors:

```fortios
config firewall policy
  edit 0                                        # Always use '0' to auto-assign ID
    set name "Allow_Client_to_Server"
    set srcintf "<lan_interface>"               # Verified from Step 1
    set dstintf "<wan_or_server_interface>"     # Verified from Step 1
    set srcaddr "H_<client_ip>"                  # Created in Step 2
    set dstaddr "H_<server_ip>"                  # Created in Step 2
    set action accept
    set schedule "always"
    set service "SVC_Custom_<port>"             # Created in Step 2
    set nat enable                              # Enable for Internet, disable for internal
    set logtraffic all                          # Log for troubleshooting
    set comments "Created via CLI step-by-step workflow"
  next
end
```

#### STEP 4: Find Auto-Assigned ID & Move Higher in Rule Priority
Because `edit 0` auto-assigns an ID at the bottom of the table, check its ID and move it before broad rules:

```fortios
# 1. Find the newly created rule's ID number:
show firewall policy | grep -B 1 -A 4 "Allow_Client_to_Server"

# Example output:
# edit 37
#     set name "Allow_Client_to_Server"

# 2. Move rule 37 before broad rule 5 so it evaluates first:
config firewall policy
  move 37 before 5
end

# 3. Verify rule placement:
show firewall policy
```

#### STEP 5: Verify Traffic Hits in Real-Time
Generate traffic from the client PC and confirm FortiOS is processing it:

```fortios
# 1. Check packet & byte counters on the new rule (e.g., ID 37):
diagnose firewall iprope show 100004 37

# 2. Stream traffic logs for this client in CLI:
execute log filter category 0
execute log filter field srcip <client_ip>
execute log filter view-lines 10
execute log display
execute log filter reset
```

---

### Dependency Reference Matrix for Common Operations

| Operation | Mandatory Prerequisites Needed First | How to Create Missing Prereq | Policy / Master Command |
|---|---|---|---|
| **Outbound Internet Policy** | Ingress LAN port, WAN port, Source Address, Service | `config firewall address` | `config firewall policy` (NAT: `enable`) |
| **Internal Server Policy** | Client IP, Server IP, Custom Port Service | `config firewall address`<br>`config firewall service custom` | `config firewall policy` (NAT: `disable`) |
| **VIP / Port Forwarding** | WAN Public IP, Internal Server IP, Port | `config firewall vip` | `config firewall policy` (`dstaddr` = VIP Name, NAT: `disable`) |
| **Static Route** | Egress interface, Next-hop Gateway IP in same subnet | Verify ARP: `get system arp` | `config router static` (`dst`, `gateway`, `device`) |
| **Site-to-Site IPsec VPN** | Remote Peer IP, PSK Secret, Local/Remote Subnets | Phase 1: `config vpn ipsec phase1-interface`<br>Phase 2: `config vpn ipsec phase2-interface` | Route: `config router static`<br>Policies: Bidirectional `config firewall policy` |
| **VLAN Sub-Interface** | Physical parent trunk port, 802.1Q VLAN ID | `config system interface` (`set type vlan`) | DHCP: `config system dhcp server`<br>Policy: `config firewall policy` |

---

## 0.3 FortiOS CLI Syntax Shield & Parse Error Prevention Guide

FortiOS CLI parsing is strict. A single missing quote or misplaced space will cause `command parse error` or abort your session. Use this guide to prevent syntax errors across **FortiOS 6.4, 7.0, 7.2, 7.4, and 7.6**.

### 1. The Double-Quote Rule (Mandatory for Names with Spaces/Symbols)
* **The Error**:
  ```text
  FGT # set srcaddr Internal Web Server
  command parse error before 'Web'
  Command fail. Return code -61
  ```
* **Why it happens**: FortiOS interprets spaces as argument delimiters.
* **The Fix**: ALWAYS wrap object names, interface names, and comments in `"double quotes"`.
  ```fortios
  set srcaddr "Internal Web Server"             # Correct!
  ```

### 2. Multi-Value Fields: Spaces ONLY, Never Commas
* **The Error**:
  ```text
  FGT # set service HTTP, HTTPS, DNS
  node_check_object fail! for service HTTP,
  Command fail. Return code -61
  ```
* **Why it happens**: Unlike Cisco or Linux tools, FortiOS does NOT use commas.
* **The Fix**: Separate multiple items with a **space**, and quote each item individually:
  ```fortios
  set service "HTTP" "HTTPS" "DNS"              # Correct!
  set srcintf "port1" "port2"                   # Correct!
  ```

### 3. Subnet Masks: Dotted-Decimal is Universally Compatible
* **The Error**:
  ```text
  FGT (address) # set subnet 192.168.1.0/24
  value parse error before '192.168.1.0/24'
  ```
* **Why it happens**: Older FortiOS versions (6.0, 6.2, 6.4) and certain subtrees require space-separated dotted-decimal netmasks (`IP MASK`).
* **The Fix**: Use `IP MASK` notation everywhere—it is **100% compatible across every FortiOS version**:
  ```fortios
  set subnet 192.168.1.0 255.255.255.0          # Subnet (/24)
  set subnet 192.168.1.100 255.255.255.255      # Single Host (/32)
  set dst 10.20.30.0 255.255.255.0              # Static Route
  ```

### 4. The Central SNAT vs Policy NAT Conflict
* **The Error**:
  ```text
  FGT (policy) # set nat enable
  attribute set fail for nat
  Command fail. Return code -1
  ```
* **Why it happens**: Your firewall has **Central SNAT** enabled globally. In Central SNAT mode, NAT configuration inside individual firewall policies is locked out.
* **How to Check**:
  ```fortios
  get system settings | grep central-nat
  # If output shows: central-nat: enable
  ```
* **The Fix**: If Central SNAT is enabled, leave `set nat` out of the firewall policy and configure NAT under Central SNAT:
  ```fortios
  config firewall central-snat-map
    edit 0
      set srcintf "<lan_interface>"
      set dstintf "wan1"
      set orig-addr "H_<client_ip>"
      set dst-addr "all"
      set nat-ippool "wan1"
    next
  end
  ```

### 5. `utm-status enable` Deprecation in FortiOS 7.2 / 7.4 / 7.6
* **Behavior Change**:
  - In **FortiOS 6.4 & 7.0**: You had to run `set utm-status enable` before attaching `set av-profile` or `set webfilter-profile`.
  - In **FortiOS 7.2 & 7.4+**: `utm-status` is deprecated and automatic. Typing `set utm-status enable` might return `unknown command` or `command parse error`.
* **The Universal Rule**: If `set utm-status enable` fails on your FortiGate, simply omit that line and apply the security profile directly:
  ```fortios
  # On 7.2+: Simply set the profile directly:
  set ssl-ssh-profile "certificate-inspection"
  set av-profile "default"
  set webfilter-profile "default"
  ```

### 6. Case Sensitivity in FortiOS CLI
* **Important**: Object names in FortiOS are **STRICTLY CASE-SENSITIVE**!
  - `"H_WebServer"` is NOT the same as `"H_webserver"`.
  - If you created `"H_WebServer"` and type `set srcaddr "H_webserver"`, FortiOS will throw:
    `node_check_object fail! for srcaddr H_webserver`
* **Best Practice**: Use an established prefix convention in uppercase, e.g., `H_` (Host), `NET_` (Subnet), `SVC_` (Service), `GRP_` (Group), `VIP_` (Virtual IP).

### 7. In-Line CLI Help & Auto-Completion (`?` and `<TAB>`)
When you are unsure of the exact syntax or available object names:
```fortios
# Type '?' after any command to see all valid parameters:
set srcintf ?

# Type '?' inside quotes to list all existing address objects:
set srcaddr ?

# Press <TAB> to auto-complete commands and object names:
set srcaddr "H_192<TAB>                         # Auto-completes to "H_192.168.1.100"
```

---

## 0.4 Interface Creation & Trunking CLI Manual (Physical, VLAN, LACP Aggregate, Loopback)

In FortiOS, interfaces must be created and configured before assigning IP addresses, DHCP scopes, or firewall policies.

### 1. Physical Interface IP & Management Access
```fortios
config system interface
  edit "<interface>"                            # [CHANGE]: e.g., "port1", "internal", "wan1"
    set vdom "root"                             # [KEEP]: Root VDOM
    set mode static                             # [KEEP]: Static IP (or change to 'dhcp' for DHCP WAN)
    set ip <fortigate_ip> 255.255.255.0         # [CHANGE]: Interface IP & subnet mask
    set allowaccess ping https ssh fgfm fabric  # [CHANGE]: Administrative protocols permitted on this port
    set status up                               # [KEEP]: Enable the port (use 'set status down' to disable)
    set speed auto                              # [KEEP]: Auto-negotiate 1G/10G/25G speed
    set description "Main Office LAN Core"      # [CHANGE]: Description
  next
end
```

### 2. 802.1Q VLAN Sub-Interface on Trunk Port
Use this when multiple departments (e.g., VLAN 10 Users, VLAN 20 Guests, VLAN 30 VoIP) share a physical trunk port to a managed switch.

```fortios
config system interface
  edit "VLAN20_Guest"                           # [CHANGE]: Unique name for this VLAN interface
    set vdom "root"                             # [KEEP]: Root VDOM
    set ip 192.168.20.1 255.255.255.0           # [CHANGE]: Gateway IP for this VLAN
    set allowaccess ping https ssh              # [CHANGE]: Allowed management services
    set interface "<lan_interface>"             # [CHANGE]: Physical parent trunk port (e.g., "port1")
    set vlanid 20                               # [CHANGE]: 802.1Q VLAN Tag ID (1 to 4094)
    set description "Guest WiFi VLAN"           # [CHANGE]: Description
  next
end
```

### 3. 802.3ad LACP Aggregate Interface (Link Aggregation / Port Bonding)
Combines two or more physical ports into a single high-bandwidth, redundant channel (e.g. 2x10G = 20G).
> **Prerequisite:** Ports must **not** have an IP address, must **not** be in a hardware switch, and must have **zero** policy references before bonding. Run `diagnose sys checkused system.interface.name "port3"` first.

```fortios
config system interface
  edit "AGG_Core_Trunk"                         # [CHANGE]: Name for your aggregate interface
    set vdom "root"                             # [KEEP]: Root VDOM
    set type aggregate                          # [KEEP]: LACP 802.3ad aggregate mode
    set member "port3" "port4"                  # [CHANGE]: Physical ports to bond together
    set lacp-mode active                        # [KEEP]: Active LACP negotiation
    set ip 10.10.10.1 255.255.255.0             # [CHANGE]: IP address of the bonded interface
    set allowaccess ping https ssh              # [CHANGE]: Management services
    set description "Dual-port LACP trunk"      # [CHANGE]: Description
  next
end
```

### 4. Loopback Interface (Stable Management & BGP Router-ID)
A virtual interface that **never goes down**. Essential for BGP router IDs, management loops, and VPN tunnel endpoints.

```fortios
config system interface
  edit "LOOPBACK_MGMT"                          # [CHANGE]: Loopback name
    set vdom "root"                             # [KEEP]: Root VDOM
    set type loopback                           # [KEEP]: Tells FortiOS this is a loopback
    set ip 10.255.255.1 255.255.255.255         # [CHANGE]: Dedicated /32 IP address
    set allowaccess ping https ssh              # [KEEP]: Management access
    set description "Router-ID and Out-of-Band" # [CHANGE]: Description
  next
end
```

---

## 0.5 SD-WAN CLI Architecture (ISPs + VPN Overlay Tunnels)

FortiOS SD-WAN unifies multiple WAN links (primary ISP, backup ISP, 4G LTE, and IPsec VPN overlays) into intelligent logical zones with real-time Performance SLA probing.

```
       ┌───────────────────────────┐
       │   SD-WAN Logical Zone     │
       │    "Underlay_Internet"    │
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
[ Member 1: wan1 ]          [ Member 2: wan2 ]
 Primary Fiber ISP           Secondary Cable ISP
  (GW: 198.51.100.1)          (GW: 203.0.113.1)
       │                           │
       └─────────────┬─────────────┘
                     ▼
       ┌───────────────────────────┐
       │   Performance SLA Check   │
       │  Pings 8.8.8.8 & 1.1.1.1  │
       │ Latency < 50ms, Loss < 2% │
       └───────────────────────────┘
```

### 1. Step-by-Step SD-WAN CLI Configuration

```fortios
# STEP 1: Create SD-WAN Logical Zones
config system sdwan
  config zone
    edit "Underlay_Internet"                    # [CHANGE]: Zone for public Internet ISPs
    next
    edit "Overlay_VPN"                          # [CHANGE]: Zone for site-to-site IPsec tunnels
    next
  end
end

# STEP 2: Add Members (WAN Ports & IPsec Tunnels) to the Zones
config system sdwan
  config members
    edit 1                                      # [KEEP]: Member ID 1
      set interface "wan1"                      # [CHANGE]: Primary ISP WAN port
      set zone "Underlay_Internet"              # [KEEP]: Binds to Internet zone
      set gateway <isp_gateway_ip>              # [CHANGE]: Next-hop gateway IP from ISP 1
    next
    edit 2                                      # [KEEP]: Member ID 2
      set interface "wan2"                      # [CHANGE]: Secondary ISP WAN port
      set zone "Underlay_Internet"              # [KEEP]: Binds to Internet zone
      set gateway <secondary_isp_gateway_ip>    # [CHANGE]: Next-hop gateway IP from ISP 2
    next
    edit 3                                      # [KEEP]: Member ID 3
      set interface "<tunnel_name>"             # [CHANGE]: IPsec tunnel interface name
      set zone "Overlay_VPN"                    # [KEEP]: Binds to VPN zone
      # Note: Point-to-point IPsec tunnels do not need a gateway parameter
    next
  end
end

# STEP 3: Configure Performance SLA (Health-Check Probes)
config system sdwan
  config health-check
    edit "SLA_DNS_Google"                       # [CHANGE]: Health check name
      set server "8.8.8.8" "1.1.1.1"            # [KEEP]: Redundant DNS probe targets
      set protocol ping                         # [KEEP]: Ping probe (or use 'http', 'dns')
      set interval 1000                         # [KEEP]: Probe every 1000 milliseconds (1s)
      set failtime 3                            # [KEEP]: 3 dropped probes = mark link degraded
      set recoverytime 5                        # [KEEP]: 5 successful probes = mark link healthy
      set members 1 2                           # [KEEP]: Tests Member 1 (wan1) and Member 2 (wan2)
      config sla
        edit 1
          set latency-threshold 50              # [CHANGE]: Max acceptable latency in ms
          set jitter-threshold 10               # [CHANGE]: Max acceptable jitter in ms
          set packetloss-threshold 2            # [CHANGE]: Max acceptable packet loss in %
        next
      end
    next
  end
end

# STEP 4: Configure SD-WAN Steering Rules (Traffic Steering)
config system sdwan
  config service
    edit 1                                      # Rule 1: Corporate Internet Steering
      set name "Steer_Internet_Traffic"
      set mode priority                         # [KEEP]: Priority failover mode
      set dst "all"                             # [KEEP]: All internet traffic
      set health-check "SLA_DNS_Google"         # [KEEP]: Links to health check in Step 3
      set priority-members 1 2                  # [KEEP]: Prefer Member 1; failover to Member 2 if SLA violated
    next
    edit 2                                      # Rule 2: Corporate VPN Steering
      set name "Steer_Remote_Branch_VPN"
      set mode priority
      set dst "NET_Remote_Branch"               # [CHANGE]: Remote office subnet object
      set priority-members 3                    # [KEEP]: Route out Member 3 (IPsec tunnel)
    next
  end
end

# STEP 5: Add Default Route Pointing to SD-WAN
config router static
  edit 0
    set dst 0.0.0.0 0.0.0.0                     # [KEEP]: All internet destinations
    set sdwan-zone "Underlay_Internet"          # [CRITICAL]: Route to SD-WAN zone (FortiOS 7.x)
    # On FortiOS 6.4/7.0: set device "sdwan"
    set comment "Default route via SD-WAN"
  next
end

# STEP 6: Firewall Policy Referencing SD-WAN Zone as Egress
config firewall policy
  edit 0
    set name "LAN_to_SDWAN_Internet"
    set srcintf "<lan_interface>"               # [CHANGE]: Ingress LAN port
    set dstintf "Underlay_Internet"             # [CRITICAL]: Egress is the SD-WAN Zone!
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat enable                              # [CRITICAL]: Must enable NAT for Internet
    set logtraffic all
  next
end
```

### 2. Monitor SD-WAN Live via CLI
```fortios
# 1. View real-time SLA metrics (Latency, Jitter, Packet Loss, Link State):
diagnose sys sdwan health-check

# 2. View which member is currently selected by SD-WAN rules:
diagnose sys sdwan service

# 3. View bandwidth & packet counters across all SD-WAN members:
diagnose sys sdwan member
```

---

## 0.6 Reference Migration Masterclass: How to Move Interfaces into SD-WAN or LACP Without Deleting Policies or Losing Configuration

### The Problem
When you try to add an existing active interface (like `wan1` or `port1`) into an SD-WAN zone or an LACP aggregate bond, FortiOS blocks you with:
```text
entry is used by another entry
Interface wan1 is used by firewall policy 1, static route 1, vip 1
Command fail. Return code -1
```
Most engineers make the mistake of deleting policies, which causes severe downtime and loses complex security profiles, comments, and rules.

### The Zero-Loss CLI Migration Procedure (Step-by-Step)

#### Step 1: Discover All Referencing Dependencies
Run this command to get the exact inventory of every configuration object using `wan1`:

```fortios
diagnose sys checkused system.interface.name "wan1"
```
*FortiOS CLI will output every referencing table, for example:*
- `firewall policy: 1, 4, 12`
- `router static: 1`
- `firewall vip: VIP_Public_443`

#### Step 2: Create the Target SD-WAN Zone First
Create the new SD-WAN zone without members so it exists in memory:
```fortios
config system sdwan
  config zone
    edit "Underlay_Internet"
    next
  end
end
```

#### Step 3: Swap Policy References Directly in CLI (Zero Policy Deletion!)
Instead of deleting policies, **swap the destination interface directly to the new SD-WAN zone**. All names, rule IDs, source IPs, security inspection profiles, and comments remain **100% preserved**:

```fortios
config firewall policy
  edit 1                                        # Policy ID found in Step 1
    set dstintf "Underlay_Internet"             # Replaces wan1 with SD-WAN zone!
  next
  edit 4                                        # Policy ID found in Step 1
    set dstintf "Underlay_Internet"
  next
  edit 12                                       # Policy ID found in Step 1
    set dstintf "Underlay_Internet"
  next
end
```

#### Step 4: Swap or Re-Point Static Routes
Static routes pointing directly to `wan1` must be re-pointed to the SD-WAN zone:

```fortios
# 1. Inspect existing static routes using wan1:
show router static 1

# 2. Repoint route 1 to SD-WAN zone:
config router static
  edit 1
    unset device                                # Removes direct wan1 binding
    set sdwan-zone "Underlay_Internet"          # Points to SD-WAN zone
  next
end
```

#### Step 5: Verify That References Reach Zero
Verify that `wan1` is completely free of dependencies:

```fortios
diagnose sys checkused system.interface.name "wan1"
```
*Output will now show:*  
`No reference found for system.interface.name wan1`

#### Step 6: Add `wan1` into SD-WAN Members Without Error
Now that `wan1` has zero references, add it into the SD-WAN zone cleanly:

```fortios
config system sdwan
  config members
    edit 1
      set interface "wan1"
      set zone "Underlay_Internet"
      set gateway <isp_gateway_ip>
    next
  end
end
```
**Result:** `wan1` is now an active SD-WAN member. All policies that you swapped in Step 3 immediately begin processing traffic through `wan1` via SD-WAN rules. **ZERO DOWNTIME, ZERO LOST POLICIES.**

---

## 0.7 Policy Routes (PBR) vs Static Routes vs SD-WAN Rules

### Kernel Routing Lookup Precedence in FortiOS
When a packet enters FortiGate, the kernel determines its egress path in this strict hierarchical order:

```
┌────────────────────────────────────────────────────────┐
│ 1. Policy-Based Routes (PBR - config router policy)    │  <-- HIGHEST PRIORITY (Matches src, dst, port)
└───────────────────────────┬────────────────────────────┘
                            │ (If no PBR match)
┌───────────────────────────▼────────────────────────────┐
│ 2. SD-WAN Rules (config system sdwan -> config service)│  <-- Evaluates SLA & link quality
└───────────────────────────┬────────────────────────────┘
                            │ (If no SD-WAN match)
┌───────────────────────────▼────────────────────────────┐
│ 3. Active FIB Table (config router static / BGP / OSPF)│  <-- Standard Destination Route Lookup
└────────────────────────────────────────────────────────┘
```

### Complete Policy-Based Route (PBR) CLI Configuration
Use PBR when you must override normal routing to force a specific user, server, or application out a secondary ISP or dedicated MPLS connection.

```fortios
config router policy
  edit 0                                        # [KEEP]: Auto-assigns ID
    set input-device "<lan_interface>"          # [CHANGE]: Ingress interface where client connects
    set src <client_ip> 255.255.255.255         # [CHANGE]: Client IP to redirect (or whole subnet)
    set dst 0.0.0.0 0.0.0.0                     # [KEEP]: Destination network (0.0.0.0/0 = all)
    set protocol 6                              # [KEEP/CHANGE]: 6 = TCP (17 = UDP, 0 = ANY)
    set start-port 443                          # [CHANGE]: Traffic port range
    set end-port 443
    set gateway <secondary_isp_gateway_ip>      # [CHANGE]: Secondary ISP router IP
    set output-device "wan2"                    # [CHANGE]: Egress WAN interface
    set comments "Force VIP executive HTTPS traffic out WAN2"
  next
end
```

### PBR Rule Order & Reordering (Top-to-Bottom)
Like firewall policies, Policy Routes are evaluated strictly top-to-bottom:

```fortios
# View all configured policy routes with their ID numbers:
show router policy

# Move policy route ID 3 BEFORE policy route ID 1 (gives rule 3 higher priority):
config router policy
  move 3 before 1
end
```

### PBR Automatic Fallback Behavior
> **Fail-Safe Mechanism:** If the next-hop gateway specified in a Policy Route goes down or becomes unreachable, FortiOS automatically bypasses the PBR rule and falls back to standard routing table (FIB). Traffic is **not** dropped unless configured otherwise!

---

## 0.8 Complete VPN CLI Deployment Manual (IPsec Site-to-Site & SSL-VPN)

### 1. Route-Based Site-to-Site IPsec VPN (IKEv2)
```fortios
# STEP 1: Phase 1 Interface
config vpn ipsec phase1-interface
  edit "<tunnel_name>"
    set interface "wan1"
    set ike-version 2
    set peertype any
    set net-device disable
    set proposal aes256-sha256 aes128-sha256
    set dpd on-idle
    set dhgrp 14 5
    set remote-gw <remote_peer_ip>
    set psksecret "YourExactComplexPsk123!"
  next
end

# STEP 2: Phase 2 Interface
config vpn ipsec phase2-interface
  edit "<tunnel_name>_p2"
    set phase1name "<tunnel_name>"
    set proposal aes256-sha256 aes128-sha256
    set dhgrp 14 5
    set auto-negotiate enable
    set src-subnet 192.168.1.0 255.255.255.0
    set dst-subnet 10.20.30.0 255.255.255.0
  next
end

# STEP 3: Route to Remote Subnet via Tunnel
config router static
  edit 0
    set dst 10.20.30.0 255.255.255.0
    set device "<tunnel_name>"
    set comment "IPsec tunnel route"
  next
end

# STEP 4: Dual Firewall Policies (No-NAT)
config firewall policy
  # Outbound: LAN to VPN
  edit 0
    set name "LAN_to_VPN"
    set srcintf "<lan_interface>"
    set dstintf "<tunnel_name>"
    set srcaddr "H_<client_ip>"
    set dstaddr "H_<server_ip>"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable                             # NEVER enable NAT across IPsec!
    set logtraffic all
  next
  # Inbound: VPN to LAN
  edit 0
    set name "VPN_to_LAN"
    set srcintf "<tunnel_name>"
    set dstintf "<lan_interface>"
    set srcaddr "H_<server_ip>"
    set dstaddr "H_<client_ip>"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable
    set logtraffic all
  next
end
```

### 2. Remote Access SSL-VPN CLI Deployment (Portal, Settings, and Policy)
```fortios
# STEP 1: Create SSL-VPN User & User Group
config user local
  edit "<username>"
    set type password
    set passwd "UserComplexPass123!"
  next
end

config user group
  edit "GRP_SSLVPN_Users"
    set member "<username>"
  next
end

# STEP 2: Create SSL-VPN Portal (Full Tunnel Mode)
config vpn ssl web portal
  edit "Full_Access_Portal"
    set tunnel-mode enable
    set ipv6-tunnel-mode disable
    set ip-pools "SSLVPN_TUNNEL_ADDR1"
  next
end

# STEP 3: Configure SSL-VPN Global Daemon Settings
config vpn ssl settings
  edit 0 # or directly modify
  set servercert "Fortinet_Factory"
  set tunnel-ip-pools "SSLVPN_TUNNEL_ADDR1"
  set source-interface "wan1"
  set source-port 10443                         # Non-standard port to avoid conflicts
  set default-portal "Full_Access_Portal"
  config authentication-rule
    edit 1
      set groups "GRP_SSLVPN_Users"
      set portal "Full_Access_Portal"
    next
  end
end

# STEP 4: Firewall Policy Permitting SSL-VPN Users to Access Internal LAN
config firewall policy
  edit 0
    set name "SSLVPN_to_Internal_LAN"
    set srcintf "ssl.root"                      # Virtual SSL-VPN interface
    set dstintf "<lan_interface>"
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set groups "GRP_SSLVPN_Users"               # Identity check on rule
    set nat enable                              # NATs to FortiGate LAN IP
    set logtraffic all
  next
end
```

---

## Quick Reference: IP Address Roles in Examples

| Placeholder | What IP it Represents | Example Value |
|---|---|---|
| `<client_ip>` / `<source_ip>` | The internal user PC or server having an issue | `192.168.1.100` |
| `<server_ip>` / `<destination_ip>` | The target server, website, or cloud service | `10.20.30.50` or `8.8.8.8` |
| `<fortigate_ip>` | FortiGate's own IP on an interface (LAN, DMZ, or WAN) | `192.168.1.1` |
| `<remote_peer_ip>` | The public IP of the remote firewall in an IPsec VPN | `203.0.113.50` |
| `<bgp_neighbor_ip>` | The ISP or upstream router's IP peering with you | `198.51.100.1` |
| `<tftp_server_ip>` | Your laptop or management server IP running a TFTP service | `192.168.1.200` |

---

## 1. Ping & Traceroute with Source Binding


### Why use it?
By default, when you ping from FortiGate CLI, it uses the outgoing WAN interface IP. If you are testing connectivity through an internal subnet or across an IPsec tunnel (where the remote firewall only permits internal subnets, not the FortiGate WAN IP), default ping will **fail**. You must bind the ping to an internal interface IP.

### Commands:

```fortios
# 1. Set the source IP to FortiGate's LAN interface IP
execute ping-options source <fortigate_lan_ip>

# 2. Ping the destination server
execute ping <destination_ip>

# 3. Always reset options when done
execute ping-options reset
```

#### What IPs to change:
- **`<fortigate_lan_ip>`**: Replace with FortiGate's own interface IP facing the target (e.g., `192.168.1.1` or internal VLAN IP `10.0.10.1`).
- **`<destination_ip>`**: Replace with the IP of the machine you want to test reaching (e.g., remote office server `10.50.1.20` or internet host `8.8.8.8`).

---

## 2. Packet Sniffer (`diagnose sniffer packet`)

### Why use it?
Use this when a user says: *"I cannot open this application/website."*
The sniffer answers:
1. Are packets arriving at the FortiGate from the user?
2. On which port/interface do they enter?
3. Does FortiGate send them out of the outgoing interface?
4. Is the server replying back?

### Command:
```fortios
diagnose sniffer packet <interface> 'host <client_ip> and host <server_ip> and port <port_number>' 4 0 l
```

#### What values to change:
- **`<interface>`**:
  - Use `any` to check all interfaces on the firewall.
  - Or specify the exact interface name, e.g., `port1`, `port2`, `wan1`, `internal`.
- **`<client_ip>`**: The IP of the user's computer or server having trouble (e.g., `192.168.1.100`).
- **`<server_ip>`**: The destination server or service IP (e.g., `10.10.20.5`).
- **`<port_number>`**: The application port:
  - `443` = HTTPS / Web
  - `80` = HTTP
  - `53` = DNS
  - `3389` = Remote Desktop (RDP)
  - `22` = SSH
  *(If you don't know the port, remove `and port <port_number>`)*.

#### Example Scenario:
Troubleshoot user `192.168.1.50` trying to reach web server `10.0.0.25` on port 443:
```fortios
diagnose sniffer packet any 'host 192.168.1.50 and host 10.0.0.25 and port 443' 4 0 l
```
*(Press `Ctrl + C` to stop capturing)*.

---

## 3. Debug Flow (`diagnose debug flow`) - The Drop & Policy Detector

### Why use it?
If packets **reach** the firewall (verified by the sniffer), but communication still fails, **Debug Flow** tells you FortiGate's internal processing decision:
- Which firewall policy ID allowed or blocked it.
- Whether it was dropped by the Implicit Deny policy (`Denied by policy 0`).
- If Source NAT (SNAT) was applied.
- If asymmetric routing caused an RPF drop (`Reverse path check failed, drop`).

### Commands:
```fortios
# 1. Reset any old filters
diagnose debug reset

# 2. Filter by the client (source) and destination
diagnose debug flow filter saddr <client_ip>
diagnose debug flow filter daddr <server_ip>
diagnose debug flow filter proto <protocol_number>
diagnose debug flow filter port <port_number>

# 3. Setup console display
diagnose debug flow show function-name enable
diagnose debug flow trace start 100
diagnose debug console timestamp enable
diagnose debug enable

# 4. Trigger traffic from client PC now

# 5. IMMEDIATELY stop debug after capturing
diagnose debug disable
diagnose debug flow trace stop
diagnose debug reset
```

#### What values to change:
- **`saddr <client_ip>`**: Source IP of the initiating device (e.g., `192.168.1.100`).
- **`daddr <server_ip>`**: Destination IP being contacted (e.g., `8.8.8.8` or `172.16.1.50`).
- **`proto <protocol_number>`**:
  - `1` = ICMP (Ping)
  - `6` = TCP (Web, RDP, SSH, Mail)
  - `17` = UDP (DNS, VoIP)
- **`port <port_number>`**: Port number (e.g., `443`, `80`, `53`).

#### How to read the output:
- `Allowed by Policy-3`: Traffic matched Policy ID 3.
- `Denied by policy 0`: **No firewall policy matched!** You need to create an allow rule.
- `Reverse path check failed, drop`: Packet dropped because return route points to a different interface (asymmetric routing).

---

## 4. Session Table Inspection & Clearing

### Why use it?
1. **Inspection**: To see if a TCP handshake completed (`state=established`) or is stuck in `state=syn_sent`.
2. **Clearing**: When you change a firewall policy or NAT rule, existing sessions stay alive using the **old** policy settings until they timeout. You clear the session to force FortiGate to apply the new policy immediately.

### Commands:
```fortios
# 1. Clear any prior session filter
diagnose sys session filter clear

# 2. Set filters to only target the affected connection
diagnose sys session filter src <client_ip>
diagnose sys session filter dst <server_ip>
diagnose sys session filter dport <port_number>

# 3. View the active session
diagnose sys session list

# 4. Clear ONLY the matching session
diagnose sys session clear

# 5. Clear the filter so future commands aren't restricted
diagnose sys session filter clear
```

#### What values to change:
- **`src <client_ip>`**: Internal device IP (e.g., `192.168.1.50`).
- **`dst <server_ip>`**: External/target server IP (e.g., `10.10.10.20`).
- **`dport <port_number>`**: Target port (e.g., `443`).

---

## 5. Routing Table Checks

### Why use it?
When you want to know: *"Which interface and next-hop gateway will FortiGate use to reach this IP?"*

### Commands:
```fortios
# Check exact best route chosen by FortiGate for an IP
get router info routing-table details <destination_ip>

# View entire active routing table (FIB)
get router info routing-table all
```

#### What IP to change:
- **`<destination_ip>`**: The IP you want to check routing for (e.g., `192.168.20.1` or `8.8.8.8`).
- **Output tells you**:
  - `via <gateway_ip>`: Next-hop router IP.
  - `is directly connected, <interface>`: Egress port.

---

## 6. Dynamic Routing: BGP Troubleshooting

### Why use it?
When BGP peering is established, but routes from your ISP or cloud (AWS/Azure) are missing.

### Commands:
```fortios
# 1. Check overall BGP neighbor states
get router info bgp summary

# 2. Check routes received from the neighbor
get router info bgp neighbors <bgp_neighbor_ip> routes

# 3. Check routes you are sending to the neighbor
get router info bgp neighbors <bgp_neighbor_ip> advertised-routes

# 4. Soft reset BGP inbound routes (non-disruptive refresh)
execute router clear bgp <bgp_neighbor_ip> soft in
```

#### What IP to change:
- **`<bgp_neighbor_ip>`**: The IP of the BGP peer/ISP router (e.g., `198.51.100.1` or Azure gateway `10.254.0.4`).

---

## 7. IPsec VPN Troubleshooting

### Why use it?
When an IPsec site-to-site VPN tunnel is DOWN or will not negotiate Phase 1 / Phase 2.

### Commands:
```fortios
# 1. View tunnel status (Up or Down)
get vpn ipsec tunnel summary

# 2. Reset debug filters
diagnose debug reset
diagnose vpn ike log-filter clear

# 3. Filter debug output ONLY for the remote firewall's WAN IP
diagnose vpn ike log-filter dst-addr4 <remote_peer_wan_ip>

# 4. Turn on IKE daemon debug
diagnose debug app ike -1
diagnose debug console timestamp enable
diagnose debug enable

# 5. Bring up/restart the tunnel to trigger negotiation
diagnose vpn ike restart <tunnel_name>

# 6. STOP debug immediately after checking output
diagnose debug disable
diagnose debug reset
```

#### What values to change:
- **`<remote_peer_wan_ip>`**: The public IP of the remote branch or partner firewall (e.g., `203.0.113.50`).
- **`<tunnel_name>`**: The name you configured for the Phase 1 interface (e.g., `VPN_Branch_NY`).

#### What to look for in output:
- `no proposal chosen`: Encryption/hash/DH-group mismatch between the two firewalls.
- `pre-shared key mismatch`: The pre-shared password doesn't match.
- `received notify: INVALID_ID_INFORMATION`: Phase 2 selector / subnets do not match.

---

## 8. SSL VPN Remote User Troubleshooting

### Why use it?
When a work-from-home user cannot log in, or their connection is frozen and needs to be dropped.

### Commands:
```fortios
# 1. See all currently connected remote users and their assigned IPs
get vpn ssl monitor

# 2. Force disconnect a user whose connection is stuck
execute vpn ssl-vpn drop-user <username>

# 3. Debug user login & authentication (LDAP / RADIUS / FortiAuthenticator)
diagnose debug reset
diagnose debug app sslvpn -1
diagnose debug app fnbamd -1         # Authentication daemon
diagnose debug console timestamp enable
diagnose debug enable

# 4. Stop debug
diagnose debug disable
diagnose debug reset
```

#### What values to change:
- **`<username>`**: The user's account name (e.g., `john.smith`).

---

## 9. ARP & MAC Address Issues

### Why use it?
When you replace a server or router connected to FortiGate, but FortiGate keeps trying to talk to the old MAC address because the ARP cache hasn't expired.

### Commands:
```fortios
# 1. View all learned MAC-to-IP bindings
get system arp

# 2. Clear ARP table on the port connected to the new device
execute clear system arp interface <interface_name>
```

#### What values to change:
- **`<interface_name>`**: The port name where the device is plugged in (e.g., `port2`, `vlan20`, `dmz`).

---

## 10. High Availability (HA) Checksum Sync & Failover

### Why use it?
When HA shows as out-of-sync, or you need to log in to the secondary firewall without moving your console cable.

### Commands:
```fortios
# 1. Check if cluster nodes have matching checksums (MUST MATCH)
diagnose sys ha checksum cluster

# 2. Connect to the secondary firewall CLI from the primary unit
execute ha manage <member_index>

# 3. Test HA failover gracefully by resetting primary uptime
diagnose sys ha reset-uptime
```

#### What values to change:
- **`<member_index>`**: Run `get system ha status` to see member IDs. Usually `1` is primary and `2` is secondary. So you would run `execute ha manage 2`.

---

## 11. Configuration Backup to TFTP Server

### Why use it?
Before upgrading firmware or making major routing changes, always create an off-box backup.

### Command:
```fortios
execute backup config tftp <backup_filename.conf> <tftp_server_ip>
```

#### What values to change:
- **`<backup_filename.conf>`**: Name you want for the file, e.g., `FG100F_backup_2026_09_23.conf`.
- **`<tftp_server_ip>`**: IP address of your workstation/laptop running a TFTP server (e.g., `192.168.1.200`).

---

## 12. Production Configuration Templates (With Line-by-Line "What to Change" Comments)

> **Golden Rule for FortiOS CLI:**
> - `edit 0`: **LEAVE AS 0.** It tells FortiGate to automatically find the next available ID number (e.g., policy ID 1, 2, 3...).
> - Words in `"quotes"`: Names you choose. Avoid spaces or keep within quotes.
> - Lines marked `# [CHANGE]`: You MUST replace this with your office network's actual name/IP.
> - Lines marked `# [KEEP]`: Standard recommended production settings; leave them as-is.

---

### 12.1 Firewall Policy: Outbound Internet Access (NAT & Security Profiles)
Use this template to give internal office computers internet access with security inspection.

```fortios
config firewall policy
  edit 0                                        # [KEEP]: '0' = FortiGate auto-assigns next free policy ID
    set name "LAN_to_Internet_Outbound"          # [CHANGE]: Give your rule a name (e.g., "Office_Internet")
    set srcintf "<lan_interface>"               # [CHANGE]: Incoming internal port (e.g., "port1", "internal", or "vlan10")
    set dstintf "wan1"                          # [CHANGE]: Outgoing WAN/Internet port (e.g., "wan1", "wan2", or "port2")
    set srcaddr "H_<client_ip>"                  # [CHANGE]: Source object (e.g., "H_192.168.1.100", an address group, or "all")
    set dstaddr "all"                           # [KEEP]: "all" allows browsing to any destination on the internet
    set action accept                           # [KEEP]: "accept" allows the traffic ("deny" would block it)
    set schedule "always"                       # [KEEP]: "always" keeps the rule active 24/7/365
    set service "HTTP" "HTTPS" "DNS"            # [CHANGE/KEEP]: Allowed ports (use "ALL", or list services like "HTTP" "HTTPS" "DNS")
    # Note: FortiOS 7.2 / 7.4 / 7.6 automatically activates UTM when profiles are assigned (do NOT use deprecated 'set utm-status enable')
    set ssl-ssh-profile "certificate-inspection"# [KEEP]: Standard certificate inspection (prevents SSL warnings on user PCs)
    set av-profile "default"                    # [OPTIONAL]: Antivirus scanning (delete line if not using AV license)
    set webfilter-profile "default"             # [OPTIONAL]: Web filtering (delete line if not using Web Filter license)
    set nat enable                              # [CRITICAL - KEEP]: MUST be 'enable' for internet access (hides private IP behind WAN IP)
    set logtraffic all                          # [CRITICAL - KEEP]: Logs all sessions under Log & Report for troubleshooting
    set logtraffic-start enable                 # [OPTIONAL]: Logs when session starts (useful when diagnosing dropped connections)
    set comments "Standard internet browsing"   # [CHANGE]: Note explaining why this rule was created and who approved it
  next
end
```

#### What you need to change for your office:
1. `<lan_interface>`: Put the interface name where your users connect (run `get system interface physical` if unsure).
2. `wan1`: Put your ISP WAN port name.
3. `H_<client_ip>`: Replace with the address object you created for this user/subnet (or put `"all"` for all office PCs).

---

### 12.2 Firewall Policy: Internal LAN to Server (No-NAT / Routing)
Use this template when an internal user needs to reach an internal server (e.g. across two different VLANs or subnets).

```fortios
config firewall policy
  edit 0                                        # [KEEP]: Auto-assigns policy ID
    set name "LAN_to_Internal_Server"           # [CHANGE]: Descriptive name for this connection
    set srcintf "<lan_interface>"               # [CHANGE]: Port where client computer is connected (e.g., "port1")
    set dstintf "<server_interface>"            # [CHANGE]: Port where server is connected (e.g., "port2" or "dmz")
    set srcaddr "H_<client_ip>"                  # [CHANGE]: Client address object (or subnet/group)
    set dstaddr "H_<server_ip>"                  # [CHANGE]: Server address object (created in section 12.3)
    set action accept                           # [KEEP]: Allows traffic
    set schedule "always"                       # [KEEP]: Active 24/7
    set service "SVC_<port>" "PING"             # [CHANGE]: Exact port needed (e.g., "HTTPS", "RDP", or custom port)
    set nat disable                             # [CRITICAL - KEEP 'disable']: NEVER enable NAT between internal subnets!
    set logtraffic all                          # [KEEP]: Logs traffic for troubleshooting
    set comments "Internal server access"       # [CHANGE]: Description
  next
end
```

#### What you need to change for your office:
1. `srcintf` & `dstintf`: Replace with your client and server interface names.
2. `srcaddr` & `dstaddr`: Must match the exact names of your address objects.
3. `nat disable`: **Do NOT touch this line.** Internal traffic must keep its real client IP so the server knows who is connecting.

---

### 12.3 Address Objects: Host, Subnet, FQDN & IP Range
Create address objects FIRST before using them in firewall policies.

```fortios
config firewall address
  # 1. Single Host (/32) - Use for a single specific PC or server
  edit "H_<client_ip>"                          # [CHANGE]: Object name (e.g., "H_192.168.1.100" or "H_PrintServer")
    set subnet <client_ip> 255.255.255.255      # [CHANGE]: Your device IP followed by 255.255.255.255 (single IP mask)
    set comment "Client workstation IP"         # [CHANGE]: Description
  next

  # 2. Entire Subnet (/24) - Use for an entire department or network
  edit "NET_Internal_LAN"                       # [CHANGE]: Subnet object name (e.g., "NET_Office_VLAN10")
    set subnet 192.168.1.0 255.255.255.0        # [CHANGE]: Network IP followed by subnet mask (e.g., 255.255.255.0)
    set comment "Office LAN subnet"             # [CHANGE]: Description
  next

  # 3. FQDN (Domain Name) - Use when cloud server has dynamic IPs (e.g., AWS, GitHub, Microsoft)
  edit "FQDN_Cloud_API"                         # [CHANGE]: Object name (e.g., "FQDN_Office365")
    set type fqdn                               # [KEEP]: Tells FortiOS this is a domain name, not an IP
    set fqdn "api.github.com"                   # [CHANGE]: The exact website domain name (do NOT include http://)
    set comment "Dynamic cloud API"             # [CHANGE]: Description
  next

  # 4. IP Range - Use for contiguous IP blocks (e.g., DHCP pool or static printer range)
  edit "RNG_Static_Printers"                    # [CHANGE]: Object name (e.g., "RNG_Printers")
    set type iprange                            # [KEEP]: Tells FortiOS this is an IP start-to-end range
    set start-ip 192.168.1.50                   # [CHANGE]: First IP in the range
    set end-ip 192.168.1.80                     # [CHANGE]: Last IP in the range
    set comment "Office printer range"          # [CHANGE]: Description
  next
end
```

#### What you need to change:
- For single IP: Use your device IP and **always** use mask `255.255.255.255`.
- For FQDN: Enter domain only (e.g., `teams.microsoft.com`). Never enter `https://`.

---

### 12.4 Address Group (`addrgrp`): Combine Multiple Objects
Use groups so you only need ONE firewall policy rule for multiple computers.

```fortios
config firewall addrgrp
  edit "GRP_Authorized_Endpoints"               # [CHANGE]: Name for your group (e.g., "GRP_Finance_Team")
    set member "H_<client_ip>" "RNG_Static_Printers" # [CHANGE]: List of address object names created in Section 12.3
    set comment "Authorized office endpoints"   # [CHANGE]: Description
  next
end
```

#### What you need to change:
- `set member "Obj1" "Obj2"`: Put the exact names of objects you already created in quotes, separated by spaces.

---

### 12.5 Custom Service Object & Service Group
Use this when your office software runs on a non-standard port (e.g. ERP on port 8088).

```fortios
# 1. Custom Single Port or Port Range
config firewall service custom
  edit "SVC_Custom_<port>"                      # [CHANGE]: Service name (e.g., "SVC_ERP_8088")
    set tcp-portrange <port>                    # [CHANGE]: The TCP port number (e.g., "8088" or range "8080-8090")
    set comment "Custom application port"       # [CHANGE]: Description
  next
end

# 2. Service Group (Combines standard ports + your custom port)
config firewall service group
  edit "GRP_Web_App_Ports"                      # [CHANGE]: Group name
    set member "HTTP" "HTTPS" "SVC_Custom_<port>" "DNS" # [CHANGE]: List of services to bundle together
    set comment "Standard web app ports"        # [CHANGE]: Description
  next
end
```

#### What you need to change:
- `set tcp-portrange`: Put your application port (e.g. `8443`). For UDP, use `set udp-portrange`.

---

### 12.6 Virtual IP (VIP / Port Forwarding / DNAT) + Inbound Policy
Use this when you have an internal server (like a web server or camera) that people on the internet need to access via your public IP.

```fortios
# STEP 1: Create the Port Forwarding (Virtual IP)
config firewall vip
  edit "VIP_Public_<port>"                      # [CHANGE]: Name for this VIP (e.g., "VIP_WebServer_443")
    set extip <public_wan_ip>                   # [CHANGE]: Your static public IP assigned by your ISP
    set mappedip "<server_ip>"                  # [CHANGE]: Internal private IP of the server (e.g., "192.168.1.50")
    set extintf "wan1"                          # [CHANGE]: Your WAN port connected to ISP (or use "any")
    set portforward enable                      # [KEEP]: Enables port forwarding
    set protocol tcp                            # [KEEP/CHANGE]: 'tcp' (or 'udp' if VoIP/gaming)
    set extport <port>                          # [CHANGE]: Port users connect to from outside (e.g., "443")
    set mappedport <port>                       # [CHANGE]: Port the server actually listens on inside (e.g., "443")
    set comment "Inbound port forward"          # [CHANGE]: Description
  next
end

# STEP 2: Create the Inbound Policy Allowing Traffic to the VIP
config firewall policy
  edit 0                                        # [KEEP]: Auto-assign policy ID
    set name "Inbound_WAN_to_VIP"               # [CHANGE]: Policy name
    set srcintf "wan1"                          # [CHANGE]: Incoming port from ISP (e.g., "wan1")
    set dstintf "<internal_server_interface>"   # [CHANGE]: Port where internal server lives (e.g., "port2")
    set srcaddr "all"                           # [KEEP]: Allows anyone on internet to connect (or change to specific partner IP)
    set dstaddr "VIP_Public_<port>"             # [CRITICAL]: MUST BE THE EXACT NAME OF THE VIP OBJECT CREATED IN STEP 1!
    set action accept                           # [KEEP]: Allows connection
    set schedule "always"                       # [KEEP]: Active 24/7
    set service "SVC_Custom_<port>"             # [CHANGE]: Port service matching the mapped port
    # Note: FortiOS 7.2 / 7.4 / 7.6 activates UTM automatically via ips-sensor:
    set ips-sensor "default"                    # [OPTIONAL]: Intrusion Prevention sensor (blocks exploits)
    set nat disable                             # [CRITICAL - KEEP 'disable']: MUST be disabled! FortiOS handles DNAT automatically.
    set logtraffic all                          # [KEEP]: Logs all inbound connection attempts
  next
end
```

#### What you need to change:
1. `extip`: Put your public static IP from your ISP.
2. `mappedip`: Put the internal private IP of your server (e.g. `10.0.0.50`).
3. In the firewall policy, `dstaddr` **must** be the name of the VIP (`"VIP_Public_<port>"`). **Do not put the private server IP here!**
4. `nat disable`: Leave this disabled.

---

### 12.7 Static Route & Policy-Based Route (PBR)
Use this to tell FortiGate how to reach networks that are not directly plugged into it.

```fortios
# 1. Specific Static Route (To reach an internal router or server subnet)
config router static
  edit 0                                        # [KEEP]: Auto-assigns route ID
    set dst <server_ip> 255.255.255.255         # [CHANGE]: Destination IP/Subnet (e.g., "10.20.30.0 255.255.255.0")
    set gateway <next_hop_gateway_ip>           # [CHANGE]: Next router IP that knows how to reach this subnet
    set device "<interface>"                    # [CHANGE]: Port on FortiGate facing that next router (e.g., "port2")
    set comment "Route to server network"       # [CHANGE]: Description
  next
end

# 2. Default Gateway Route (Out to Internet ISP)
config router static
  edit 0                                        # [KEEP]: Auto-assigns route ID
    set dst 0.0.0.0 0.0.0.0                     # [KEEP]: 0.0.0.0/0 means 'All Internet Traffic'
    set gateway <isp_gateway_ip>                # [CHANGE]: Gateway IP provided by your ISP
    set device "wan1"                           # [CHANGE]: WAN interface name
    set distance 10                             # [KEEP]: Administrative distance (10 is standard for static routes)
    set comment "Primary default route to ISP"  # [CHANGE]: Description
  next
end

# 3. Policy-Based Route (PBR) - Force specific client to use secondary WAN
config router policy
  edit 0                                        # [KEEP]: Auto-assigns policy route ID
    set input-device "<interface>"              # [CHANGE]: Ingress interface where client connects (e.g., "port1")
    set src <client_ip> 255.255.255.255         # [CHANGE]: Client IP to redirect (or subnet)
    set dst 0.0.0.0 0.0.0.0                     # [KEEP]: All destinations
    set gateway <secondary_isp_gateway_ip>      # [CHANGE]: Secondary ISP router gateway IP
    set output-device "wan2"                    # [CHANGE]: Secondary WAN port name
    set comments "Force VIP executive PC out WAN2" # [CHANGE]: Description
  next
end
```

#### What you need to change:
- `dst`: The destination IP network you are trying to reach.
- `gateway`: The next-hop router's IP address.
- `device`: The physical port on the FortiGate connected to that gateway.

```

---

## 13. Error & Log Deep-Dive Matrix: Exactly What to Find & How to Fix

### 13.1 Error: `Denied by policy 0, drop` (Implicit Deny)
* **Command to Capture**:
  ```fortios
  diagnose debug reset
  diagnose debug flow filter saddr <client_ip>
  diagnose debug flow filter daddr <server_ip>
  diagnose debug flow show function-name enable
  diagnose debug flow trace start 20
  diagnose debug enable
  ```
* **Sample Log Output**:
  ```text
  id=20085 trace_id=1 func=resolve_ip_tuple_fast line=5973 msg="Find IPv4 policy (0)"
  id=20085 trace_id=1 func=__vf_ip4_route_input line=1234 msg="Denied by policy 0, drop"
  ```
* 🎯 **CRITICAL STRING TO FIND**: `Denied by policy 0, drop`
* **Root Cause**: Policy 0 is the implicit deny rule. No firewall rule matched the incoming port, outgoing port, source IP, destination IP, or service port.
* **Exact CLI Fix**:
  ```fortios
  config firewall policy
    edit 0
      set name "Allow_<client_ip>_to_<server_ip>"
      set srcintf "<interface>"
      set dstintf "wan1"
      set srcaddr "H_<client_ip>"
      set dstaddr "H_<server_ip>"
      set action accept
      set schedule "always"
      set service "HTTPS"
      set nat enable
      set logtraffic all
    next
  end
  ```

---

### 13.2 Error: `reverse path check failed, drop` (Asymmetric Routing / RPF)
* **Command to Capture**: `diagnose debug flow` (as above)
* **Sample Log Output**:
  ```text
  id=20085 trace_id=3 func=resolve_ip_tuple_fast line=5960 msg="Find IPv4 policy (1)"
  id=20085 trace_id=3 func=rpdb_core_esr line=145 msg="reverse path check failed, drop"
  ```
* 🎯 **CRITICAL STRING TO FIND**: `reverse path check failed, drop`
* **Root Cause**: Packet arrived on interface A, but the routing table lookup for return packets to `<client_ip>` points to interface B. FortiOS drops it as anti-spoofing protection.
* **Exact CLI Fix**:
  ```fortios
  # Fix return route:
  config router static
    edit 0
      set dst <client_ip> 255.255.255.255
      set gateway <fortigate_ip>
      set device "<interface>"
    next
  end

  # Or disable strict RPF on incoming interface:
  config system interface
    edit "<interface>"
      set src-check disable
    next
  end
  ```

---

### 13.3 Error: `no proposal chosen` (IPsec Phase 1/2 Cipher Mismatch)
* **Command to Capture**:
  ```fortios
  diagnose vpn ike log-filter dst-addr4 <remote_peer_wan_ip>
  diagnose debug app ike -1
  diagnose debug enable
  diagnose vpn ike restart <tunnel_name>
  ```
* **Sample Log Output**:
  ```text
  ike 0:<tunnel_name>:12345: incoming proposal:
  ike 0:<tunnel_name>:12345:   type=ENCR, val=AES_CBC (key_len = 256)
  ike 0:<tunnel_name>:12345:   type=DH, val=MODP_2048 (Group 14)
  ike 0:<tunnel_name>:12345: no proposal chosen
  ike 0:<tunnel_name>:12345: negotiation failure
  ```
* 🎯 **CRITICAL STRING TO FIND**: `no proposal chosen`
* **Root Cause**: Remote peer proposed an encryption algorithm, hash, or DH group that does not match this FortiGate.
* **Exact CLI Fix**:
  ```fortios
  config vpn ipsec phase1-interface
    edit "<tunnel_name>"
      set proposal aes256-sha256 aes128-sha256
      set dhgrp 14 5
    next
  end
  ```

---

### 13.4 Error: `peer auth failed: preshared key mismatch` (Bad VPN Secret)
* **Command to Capture**: `diagnose debug app ike -1` (as above)
* **Sample Log Output**:
  ```text
  ike 0:<tunnel_name>:12345: compute payload AUTH
  ike 0:<tunnel_name>:12345: peer auth failed: preshared key mismatch
  ike 0:<tunnel_name>:12345: delete SA
  ```
* 🎯 **CRITICAL STRING TO FIND**: `peer auth failed: preshared key mismatch`
* **Root Cause**: The Pre-Shared Key (PSK password) on FortiGate does not match the remote firewall.
* **Exact CLI Fix**:
  ```fortios
  config vpn ipsec phase1-interface
    edit "<tunnel_name>"
      set psksecret "YourExactComplexPassword123!"
    next
  end
  diagnose vpn ike restart <tunnel_name>
  ```

---

### 13.5 Error: `received notify: INVALID_ID_INFORMATION` (Phase 2 Subnet Mismatch)
* **Command to Capture**: `diagnose debug app ike -1` (as above)
* **Sample Log Output**:
  ```text
  ike 0:<tunnel_name>:12345: local selector: 192.168.1.0/24
  ike 0:<tunnel_name>:12345: remote selector: 10.20.30.0/24
  ike 0:<tunnel_name>:12345: received notify: INVALID_ID_INFORMATION
  ```
* 🎯 **CRITICAL STRING TO FIND**: `received notify: INVALID_ID_INFORMATION`
* **Root Cause**: Phase 2 selectors (local/remote subnets) do not mirror each other.
* **Exact CLI Fix**:
  ```fortios
  config vpn ipsec phase2-interface
    edit "<tunnel_name>_p2"
      set src-subnet 192.168.1.0 255.255.255.0
      set dst-subnet 10.20.30.0 255.255.255.0
    next
  end
  ```

---

### 13.6 Error: `The system has entered conserve mode.` (RAM Exhaustion)
* **Command to Capture**: `diagnose hardware sysinfo conserve` & `diagnose sys top 2 10`
* **Sample Log Output**:
  ```text
  id=20101 level=alert msg="The system has entered conserve mode."
  id=20102 level=warning msg="Total RAM: 1980MB, Used: 1762MB (89%), Free: 218MB (11%)"
  ```
* 🎯 **CRITICAL STRING TO FIND**: `The system has entered conserve mode.`
* **Root Cause**: Memory reached >88% threshold. Proxy daemons drop connections or bypass inspection.
* **Exact CLI Fix**:
  ```fortios
  # Restart WAD proxy daemon to free leaked memory immediately:
  diagnose test application wad 99

  # Tune session retention:
  config system global
    set tcp-halfclose-timer 30
    set tcp-timewait-timer 10
  end
  ```

---

### 13.7 Error: `ldap_bind failed, return code: 49` (SSL VPN / LDAP Auth)
* **Command to Capture**: `diagnose debug app fnbamd -1` & `diagnose debug app sslvpn -1`
* **Sample Log Output**:
  ```text
  [fnbamd_ldap.c:1290]: ldap_bind failed, return code: 49 (Invalid credentials)
  [fnbamd_auth.c:450]: user '<username>' authentication failed
  ```
* 🎯 **CRITICAL STRING TO FIND**: `ldap_bind failed, return code: 49`
* **Root Cause**: Code 49 means Invalid Credentials from Active Directory (wrong password, account locked, or FortiGate bind account expired).
* **Exact CLI Fix**:
  ```fortios
  # Test user credentials directly from CLI:
  diagnose test authserver ldap "Corp_AD_LDAP" <username> "<password>"

  # Update service account password if expired:
  config user ldap
    edit "Corp_AD_LDAP"
      set password "NewServicePassword123!"
    next
  end
  ```

---

### 13.8 Error: `traffic offloaded to NP6/NP7 ASIC` (Packets Missing in Trace)
* **Command to Capture**: `diagnose debug flow`
* **Sample Log Output**:
  ```text
  id=20085 trace_id=1 func=np6_ip4_offload line=880 msg="traffic offloaded to NP6/NP7 ASIC"
  # [Subsequent packets bypass CPU and do not display in trace]
  ```
* 🎯 **CRITICAL STRING TO FIND**: `traffic offloaded to NP6/NP7 ASIC`
* **Root Cause**: FortiOS hardware network processor took over the flow. Offloaded packets bypass the CPU kernel, so sniffer and debug flow go silent.
* **Exact CLI Fix**:
  ```fortios
  config firewall policy
    edit <policy_id>
      set auto-asic-offload disable
    next
  end
  # Remember to re-enable when finished troubleshooting!
  ```

