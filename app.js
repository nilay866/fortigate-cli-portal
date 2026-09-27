/**
 * Fortinet FortiGate® CLI Diagnostics & Troubleshooting Portal
 * 100% Client-Side, Zero Database
 * Fully Loaded: Diagnostics, Deep-Dive Error Log Analyzers & Configuration Templates
 */

// Command & Template Database
const COMMANDS = [
  // =========================================================================
  // SECTION 0: PURE CLI OPERATIONS (ZERO GUI REQUIRED)
  // =========================================================================
  {
    id: "cli-policy-reorder",
    title: "CLI Policy Reorder: Move Rules Top-to-Bottom (Priority)",
    category: "cli-ops",
    tags: ["cli", "move", "policy", "reorder", "order", "top to bottom", "priority"],
    presets: ["preset-cli-ops", "preset-policy-templates"],
    whenToUse: "Firewall rules are evaluated top-to-bottom. If a broader rule above blocks traffic or catches it first, use this command in CLI to move the specific rule higher.",
    template: `config firewall policy
  # Move policy ID 25 BEFORE policy ID 5 (places rule 25 higher in priority)
  move 25 before 5

  # Move policy ID 12 AFTER policy ID 3 (places rule 12 lower in priority)
  move 12 after 3
end

# Verify the new policy order:
show firewall policy`,
    tip: "You must run 'move' while inside 'config firewall policy'. Always verify the new order with 'show firewall policy'."
  },
  {
    id: "cli-policy-hit-counter",
    title: "CLI Policy Hit Counters: Verify Packets & Bytes per Rule",
    category: "cli-ops",
    tags: ["cli", "hits", "counter", "packets", "bytes", "iprope", "policy check"],
    presets: ["preset-cli-ops", "preset-packet-drop"],
    whenToUse: "Verify if traffic is actually hitting a specific firewall policy without logging into the Web GUI.",
    template: `# Display hit counters (packets & bytes) for ALL firewall policies:
diagnose firewall iprope show 100004 0

# Check hit counter for a SPECIFIC policy ID (e.g. Policy ID 5):
diagnose firewall iprope show 100004 5`,
    tip: "If packets=0 and bytes=0, traffic is NOT matching this policy. Check IP, port, interface, or rules higher up."
  },
  {
    id: "cli-log-viewer",
    title: "CLI Log Viewer: Filter & Read Traffic Logs in Terminal",
    category: "cli-ops",
    tags: ["cli", "log", "display", "filter", "read logs", "terminal"],
    presets: ["preset-cli-ops", "preset-error-logs"],
    whenToUse: "Read real-time or historical traffic logs directly in the terminal without opening the Web GUI Log & Report page.",
    template: `# 1. Select log category (0 = Traffic, 1 = Event, 2 = Security)
execute log filter category 0

# 2. Filter by source IP, destination IP, or port:
execute log filter field srcip {{client_ip}}
execute log filter field dstip {{server_ip}}
execute log filter field dstport {{port}}

# 3. Choose how many lines to view (e.g. last 30):
execute log filter view-lines 30

# 4. Display the filtered logs:
execute log display

# 5. Always reset filter when finished:
execute log filter reset`,
    tip: "Category 0 = Traffic logs (allowed/denied sessions). Category 1 = System events (VPN up/down, admin logins)."
  },
  {
    id: "cli-check-used",
    title: "CLI Dependency Check: Find Where an Object is Used",
    category: "cli-ops",
    tags: ["cli", "checkused", "dependency", "delete error", "in use"],
    presets: ["preset-cli-ops", "preset-object-templates"],
    whenToUse: "Run before deleting an address or service object to find which policies or groups reference it (prevents 'object is used by another entry' error).",
    template: `# Check where an Address Object is used:
diagnose sys checkused firewall.address.name "H_{{client_ip}}"

# Check where an Address Group is used:
diagnose sys checkused firewall.addrgrp.name "GRP_Authorized_Endpoints"

# Check where a Custom Service is used:
diagnose sys checkused firewall.service.custom.name "SVC_Custom_{{port}}"`,
    tip: "FortiOS refuses to delete any object that is still bound to an active firewall policy, VIP, or group."
  },
  {
    id: "cli-policy-disable-enable",
    title: "CLI Policy Toggle: Disable or Enable Rule Without Deleting",
    category: "cli-ops",
    tags: ["cli", "disable", "enable", "status", "test rule"],
    presets: ["preset-cli-ops", "preset-policy-templates"],
    whenToUse: "Temporarily turn off a rule for troubleshooting without losing its configuration.",
    template: `config firewall policy
  edit 5                                        # [CHANGE]: Policy ID number
    set status disable                          # Temporarily disables rule
    # set status enable                         # Run this to re-enable rule
  next
end`,
    tip: "A disabled policy will not evaluate traffic but preserves all NAT, schedule, and security settings."
  },
  {
    id: "cli-delete-clean",
    title: "CLI Object Deletion: Delete Policy, Address, or Service",
    category: "cli-ops",
    tags: ["cli", "delete", "remove", "clean", "purge"],
    presets: ["preset-cli-ops"],
    whenToUse: "Purge obsolete rules, decommissioned servers, or old address objects directly from the terminal.",
    template: `# Delete a Firewall Policy by ID:
config firewall policy
  delete 5                                      # [CHANGE]: Policy ID number to delete
end

# Delete an Address Object:
config firewall address
  delete "H_{{client_ip}}"                      # [CHANGE]: Object name to delete
end

# Delete an Address Group:
config firewall addrgrp
  delete "GRP_Authorized_Endpoints"             # [CHANGE]: Group name to delete
end`,
    tip: "If deletion returns 'entry is used by another entry', run 'diagnose sys checkused' to find and remove the policy reference first."
  },

  // =========================================================================
  // SECTION 0.2: STEP-BY-STEP PREREQUISITE & POLICY BUILDER WORKFLOWS
  // =========================================================================
  {
    id: "workflow-policy-creation",
    title: "5-Step Policy Creation: Find Objects -> Create Missing -> Assemble -> Reorder -> Test",
    category: "workflow",
    tags: ["workflow", "step by step", "policy", "prerequisites", "find first", "move", "iprope", "bottom up"],
    presets: ["preset-workflow", "preset-policy-templates", "preset-cli-ops"],
    whenToUse: "Use this end-to-end workflow when creating a firewall policy from scratch. Verifies interfaces, address objects, and services exist before policy creation, preventing 'node_check_object fail!' errors.",
    template: `# -------------------------------------------------------------
# STEP 1: DISCOVER / FIND EXISTING OBJECTS & INTERFACES FIRST
# -------------------------------------------------------------
# Check interface names (ensure ports are UP):
get system interface physical
show system interface ?

# Check if client/source address object already exists:
get firewall address | grep -i "{{client_ip}}"
show firewall address "H_{{client_ip}}"

# Check if destination server address object already exists:
get firewall address | grep -i "{{server_ip}}"
show firewall address "H_{{server_ip}}"

# Check if service port already exists:
get firewall service custom | grep -i "{{port}}"
show firewall service custom "SVC_Custom_{{port}}"

# -------------------------------------------------------------
# STEP 2: CREATE ANY MISSING PREREQUISITES (IF NOT FOUND IN STEP 1)
# -------------------------------------------------------------
# Create Source Address Object (if missing):
config firewall address
  edit "H_{{client_ip}}"
    set subnet {{client_ip}} 255.255.255.255
    set comment "Client workstation IP"
  next
end

# Create Destination Address Object (if missing):
config firewall address
  edit "H_{{server_ip}}"
    set subnet {{server_ip}} 255.255.255.255
    set comment "Target destination IP"
  next
end

# Create Custom Service Port (if missing):
config firewall service custom
  edit "SVC_Custom_{{port}}"
    set tcp-portrange {{port}}
    set comment "Application TCP port"
  next
end

# -------------------------------------------------------------
# STEP 3: ASSEMBLE THE FIREWALL POLICY (NOW 100% SAFE FROM ERRORS)
# -------------------------------------------------------------
config firewall policy
  edit 0                                        # [KEEP]: Auto-assigns next free policy ID
    set name "Allow_{{client_ip}}_to_{{server_ip}}" # [CHANGE]: Rule name
    set srcintf "{{interface}}"                 # [CHANGE]: Ingress port (e.g. "port1" or "internal")
    set dstintf "wan1"                          # [CHANGE]: Egress port (e.g. "wan1" or "port2")
    set srcaddr "H_{{client_ip}}"               # [KEEP/CHANGE]: Verified from Step 2
    set dstaddr "H_{{server_ip}}"               # [KEEP/CHANGE]: Verified from Step 2
    set action accept                           # [KEEP]: Allow traffic
    set schedule "always"                       # [KEEP]: 24/7 schedule
    set service "SVC_Custom_{{port}}"           # [KEEP/CHANGE]: Verified from Step 2
    set nat enable                              # [KEEP]: Enable for Internet; change to 'disable' for internal LAN
    set logtraffic all                          # [CRITICAL]: Logs sessions for troubleshooting
    set comments "Created via CLI 5-step workflow"
  next
end

# -------------------------------------------------------------
# STEP 4: FIND AUTO-ASSIGNED ID & MOVE HIGHER IN RULE ORDER
# -------------------------------------------------------------
# Find the new policy ID number:
show firewall policy | grep -B 1 -A 3 "Allow_{{client_ip}}_to_{{server_ip}}"

# Move rule (e.g. if ID is 42, place it before broad rule 5):
config firewall policy
  move 42 before 5
end

# -------------------------------------------------------------
# STEP 5: VERIFY TRAFFIC HITS & LOGS IN REAL-TIME
# -------------------------------------------------------------
# Check packet/byte counters on rule 42:
diagnose firewall iprope show 100004 42

# View real-time logs for this client IP:
execute log filter category 0
execute log filter field srcip {{client_ip}}
execute log filter view-lines 10
execute log display
execute log filter reset`,
    tip: "Never run 'config firewall policy' until all srcaddr, dstaddr, and service objects exist. If you get 'node_check_object fail!', an object was mistyped or missing."
  },
  {
    id: "workflow-vip-creation",
    title: "Step-by-Step VIP & Port Forwarding: Check IPs -> Create VIP -> Policy -> Test",
    category: "workflow",
    tags: ["workflow", "vip", "dnat", "port forward", "inbound", "server publish"],
    presets: ["preset-workflow", "preset-vip-templates"],
    whenToUse: "Publish an internal server (web, SSH, camera) to the Internet. FortiOS requires creating the VIP object FIRST, and then using the VIP NAME as the dstaddr in the firewall policy (never the internal IP).",
    template: `# -------------------------------------------------------------
# STEP 1: DISCOVER PUBLIC IP & INTERNAL SERVER REACHABILITY
# -------------------------------------------------------------
# Check WAN interface IP:
get system interface physical
show system interface "wan1"

# Verify FortiGate can reach internal server IP:
execute ping-options source {{fortigate_ip}}
execute ping {{server_ip}}
execute ping-options reset

# -------------------------------------------------------------
# STEP 2: CREATE VIRTUAL IP OBJECT (DNAT MAPPING)
# -------------------------------------------------------------
config firewall vip
  edit "VIP_Public_{{port}}"                    # [CHANGE]: VIP object name
    set extip {{peer_ip}}                       # [CHANGE]: Your public WAN static IP
    set mappedip "{{server_ip}}"                # [CHANGE]: Internal private IP of server
    set extintf "wan1"                          # [CHANGE]: WAN port connected to ISP
    set portforward enable                      # [KEEP]: Enables port forwarding
    set protocol tcp                            # [KEEP/CHANGE]: 'tcp' or 'udp'
    set extport {{port}}                        # [CHANGE]: External port users connect to
    set mappedport {{port}}                     # [CHANGE]: Internal port server listens on
    set comment "Inbound port forwarding to internal server"
  next
end

# -------------------------------------------------------------
# STEP 3: CREATE INBOUND POLICY ALLOWING TRAFFIC TO VIP
# -------------------------------------------------------------
config firewall policy
  edit 0                                        # [KEEP]: Auto-assigns ID
    set name "Inbound_WAN_to_VIP_{{port}}"      # [CHANGE]: Policy name
    set srcintf "wan1"                          # [CHANGE]: Incoming WAN port
    set dstintf "{{interface}}"                 # [CHANGE]: Internal interface where server lives
    set srcaddr "all"                           # [KEEP]: Allow all external visitors (or restrict to partner IPs)
    set dstaddr "VIP_Public_{{port}}"           # [CRITICAL]: MUST BE THE VIP OBJECT NAME (NOT THE SERVER IP!)
    set action accept                           # [KEEP]: Allow traffic
    set schedule "always"                       # [KEEP]: 24/7 schedule
    set service "ALL"                           # [KEEP]: VIP handles port translation; 'ALL' or custom service
    # Note: On FortiOS 7.2/7.4/7.6, applying ips-sensor or av-profile automatically activates UTM inspection:
    set ips-sensor "default"                    # [OPTIONAL]: Protect server from exploits (FortiOS 7.2/7.4/7.6)
    set nat disable                             # [CRITICAL]: MUST BE 'disable'! VIP handles DNAT automatically
    set logtraffic all                          # [KEEP]: Log all inbound hits
  next
end

# -------------------------------------------------------------
# STEP 4: REORDER & VERIFY
# -------------------------------------------------------------
# Find rule ID and place above general deny rules:
show firewall policy | grep -B 1 -A 3 "Inbound_WAN_to_VIP"

# Check active translation table:
diagnose firewall vip list | grep -i "VIP_Public_{{port}}"

# Monitor inbound connections live:
diagnose sniffer packet wan1 'host {{peer_ip}} and port {{port}}' 4 0 l`,
    tip: "Critical Trap: In the firewall policy, setting 'dstaddr' to the private server IP instead of the VIP name is the #1 reason port forwarding fails."
  },
  {
    id: "workflow-route-creation",
    title: "Step-by-Step Static Route: Verify Gateway & ARP -> Create Route -> Check FIB",
    category: "workflow",
    tags: ["workflow", "route", "static route", "gateway", "arp", "fib"],
    presets: ["preset-workflow", "preset-route-templates"],
    whenToUse: "Route traffic to a remote subnet or downstream router. FortiOS requires the next-hop gateway IP to be directly reachable on the selected interface.",
    template: `# -------------------------------------------------------------
# STEP 1: VERIFY NEXT-HOP GATEWAY REACHABILITY & ARP
# -------------------------------------------------------------
# Ensure the interface facing the router is UP and configured:
show system interface "{{interface}}"

# Ping next-hop gateway:
execute ping {{fortigate_ip}}

# Verify ARP resolution for next-hop gateway:
get system arp | grep "{{fortigate_ip}}"

# -------------------------------------------------------------
# STEP 2: CREATE STATIC ROUTE
# -------------------------------------------------------------
config router static
  edit 0                                        # [KEEP]: Auto-assigns route ID
    set dst {{server_ip}} 255.255.255.0         # [CHANGE]: Destination network & dotted netmask
    set gateway {{fortigate_ip}}                # [CHANGE]: Next-hop router IP
    set device "{{interface}}"                  # [CHANGE]: Egress interface
    set distance 10                             # [KEEP]: Administrative distance (10 is standard)
    set priority 1                              # [KEEP]: Metric priority
    set comment "Static route to remote subnet" # [CHANGE]: Description
  next
end

# -------------------------------------------------------------
# STEP 3: VERIFY ROUTE IS INSTALLED IN ACTIVE ROUTING TABLE (FIB)
# -------------------------------------------------------------
# Check if route appears in RIB:
get router info routing-table details {{server_ip}}

# Check if route is installed in FortiOS Kernel FIB (Hardware forwarding):
get router info kernel | grep -i "{{server_ip}}"

# -------------------------------------------------------------
# STEP 4: VERIFY RETURN PATH ROUTING (PREVENT RPF DROP)
# -------------------------------------------------------------
# Test reverse path lookup:
get router info routing-table details {{client_ip}}`,
    tip: "If a static route does not appear in 'get router info routing-table all', verify that the gateway IP belongs to the same subnet as the FortiGate interface IP."
  },
  {
    id: "workflow-ipsec-creation",
    title: "Step-by-Step IPsec VPN: Phase 1 -> Phase 2 -> Route -> Dual Policies -> Bring Up",
    category: "workflow",
    tags: ["workflow", "vpn", "ipsec", "phase 1", "phase 2", "tunnel", "ike"],
    presets: ["preset-workflow", "preset-vpn-down"],
    whenToUse: "Deploy a route-based site-to-site IPsec VPN tunnel between two offices completely via CLI.",
    template: `# -------------------------------------------------------------
# STEP 1: VERIFY WAN CONNECTIVITY & DEFINE LOCAL/REMOTE SUBNETS
# -------------------------------------------------------------
# Ping remote peer public IP:
execute ping {{peer_ip}}

# Create Local Subnet Address Object:
config firewall address
  edit "NET_Local_Office"
    set subnet 192.168.1.0 255.255.255.0
  next
  # Create Remote Subnet Address Object:
  edit "NET_Remote_Branch"
    set subnet 10.20.30.0 255.255.255.0
  next
end

# -------------------------------------------------------------
# STEP 2: CREATE IPSEC PHASE 1 INTERFACE
# -------------------------------------------------------------
config vpn ipsec phase1-interface
  edit "{{tunnel_name}}"
    set interface "wan1"                        # [CHANGE]: Egress WAN port
    set ike-version 2                           # [KEEP]: IKEv2 is modern standard
    set peertype any                            # [KEEP]: Any peer type
    set net-device disable                      # [KEEP]: Pure route-based tunnel
    set proposal aes256-sha256 aes128-sha256    # [KEEP]: Matching encryption
    set dpd on-idle                             # [KEEP]: Dead Peer Detection
    set dhgrp 14 5                              # [KEEP]: Diffie-Hellman groups
    set remote-gw {{peer_ip}}                   # [CHANGE]: Remote firewall public IP
    set psksecret "YourSecurePskSecret123!"     # [CHANGE]: Pre-shared key password
  next
end

# -------------------------------------------------------------
# STEP 3: CREATE IPSEC PHASE 2 INTERFACE
# -------------------------------------------------------------
config vpn ipsec phase2-interface
  edit "{{tunnel_name}}_p2"
    set phase1name "{{tunnel_name}}"            # [KEEP]: Binds to Phase 1 created above
    set proposal aes256-sha256 aes128-sha256    # [KEEP]: Matching encryption
    set dhgrp 14 5                              # [KEEP]: DH group
    set auto-negotiate enable                   # [KEEP]: Keep tunnel alive
    set src-subnet 192.168.1.0 255.255.255.0    # [CHANGE]: Local subnet
    set dst-subnet 10.20.30.0 255.255.255.0     # [CHANGE]: Remote subnet
  next
end

# -------------------------------------------------------------
# STEP 4: CREATE STATIC ROUTE TO REMOTE SUBNET VIA TUNNEL
# -------------------------------------------------------------
config router static
  edit 0
    set dst 10.20.30.0 255.255.255.0            # [CHANGE]: Remote office subnet
    set device "{{tunnel_name}}"                # [KEEP]: Virtual IPsec interface name
  next
end

# -------------------------------------------------------------
# STEP 5: CREATE DUAL FIREWALL POLICIES (OUTBOUND & INBOUND, NO-NAT)
# -------------------------------------------------------------
config firewall policy
  # Policy 1: Outbound (Local to Remote)
  edit 0
    set name "VPN_Outbound_{{tunnel_name}}"
    set srcintf "{{interface}}"
    set dstintf "{{tunnel_name}}"
    set srcaddr "NET_Local_Office"
    set dstaddr "NET_Remote_Branch"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable                             # [CRITICAL]: NEVER enable NAT across IPsec!
    set logtraffic all
  next
  # Policy 2: Inbound (Remote to Local)
  edit 0
    set name "VPN_Inbound_{{tunnel_name}}"
    set srcintf "{{tunnel_name}}"
    set dstintf "{{interface}}"
    set srcaddr "NET_Remote_Branch"
    set dstaddr "NET_Local_Office"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable                             # [CRITICAL]: NEVER enable NAT across IPsec!
    set logtraffic all
  next
end

# -------------------------------------------------------------
# STEP 6: BRING UP TUNNEL & VERIFY STATUS
# -------------------------------------------------------------
diagnose vpn ike restart {{tunnel_name}}
get vpn ipsec tunnel summary
diagnose vpn tunnel list name {{tunnel_name}}`,
    tip: "Both sides of the IPsec tunnel must mirror each other: FortiGate Local Subnet = Remote Peer Remote Subnet, and NAT MUST be disabled on both policies."
  },
  {
    id: "workflow-vlan-creation",
    title: "Step-by-Step VLAN & DHCP: Trunk Port -> VLAN Tag/IP -> DHCP Pool -> Policy",
    category: "workflow",
    tags: ["workflow", "vlan", "subinterface", "dhcp", "trunk", "802.1q"],
    presets: ["preset-workflow", "preset-policy-templates"],
    whenToUse: "Create a new department VLAN (e.g., VLAN 20 for Guest or VoIP) with its own gateway IP, DHCP pool, and internet access policy.",
    template: `# -------------------------------------------------------------
# STEP 1: IDENTIFY PHYSICAL TRUNK INTERFACE
# -------------------------------------------------------------
# Verify physical switch-facing port is UP:
get system interface physical
show system interface "port1"

# -------------------------------------------------------------
# STEP 2: CREATE 802.1Q VLAN SUB-INTERFACE
# -------------------------------------------------------------
config system interface
  edit "VLAN20_Guest"                           # [CHANGE]: Interface name
    set vdom "root"                             # [KEEP]: Root VDOM
    set ip 192.168.20.1 255.255.255.0           # [CHANGE]: Gateway IP for this VLAN
    set allowaccess ping https ssh              # [CHANGE]: Management services allowed
    set interface "port1"                       # [CHANGE]: Physical parent trunk interface
    set vlanid 20                               # [CHANGE]: 802.1Q VLAN Tag ID (1-4094)
    set description "Guest WiFi VLAN"           # [CHANGE]: Description
  next
end

# -------------------------------------------------------------
# STEP 3: CONFIGURE DHCP SERVER ON THIS VLAN
# -------------------------------------------------------------
config system dhcp server
  edit 0                                        # [KEEP]: Auto-assigns ID
    set status enable                           # [KEEP]: Activates DHCP
    set default-gateway 192.168.20.1            # [CHANGE]: VLAN gateway IP
    set netmask 255.255.255.0                   # [CHANGE]: Netmask
    set interface "VLAN20_Guest"                # [CHANGE]: Binds to VLAN created in Step 2
    config ip-range
      edit 1
        set start-ip 192.168.20.100             # [CHANGE]: First assignable IP
        set end-ip 192.168.20.200               # [CHANGE]: Last assignable IP
      next
    end
    set dns-server1 8.8.8.8                     # [CHANGE]: Primary DNS
    set dns-server2 1.1.1.1                     # [CHANGE]: Secondary DNS
  next
end

# -------------------------------------------------------------
# STEP 4: CREATE FIREWALL POLICY ALLOWING VLAN INTERNET ACCESS
# -------------------------------------------------------------
config firewall policy
  edit 0
    set name "VLAN20_to_Internet"
    set srcintf "VLAN20_Guest"                  # [CHANGE]: Source VLAN interface
    set dstintf "wan1"                          # [CHANGE]: WAN port
    set srcaddr "all"                           # [KEEP]: All VLAN users
    set dstaddr "all"                           # [KEEP]: Internet destinations
    set action accept                           # [KEEP]: Allow
    set schedule "always"
    set service "HTTP" "HTTPS" "DNS"
    set nat enable                              # [CRITICAL]: Must enable NAT for Internet
    set logtraffic all
  next
end

# -------------------------------------------------------------
# STEP 5: VERIFY LEASES & TRAFFIC
# -------------------------------------------------------------
# View active DHCP client leases:
show system dhcp server | grep -A 10 "VLAN20_Guest"

# Sniff DHCP requests (ports 67/68):
diagnose sniffer packet VLAN20_Guest 'port 67 or port 68' 4 0 l`,
    tip: "Ensure the upstream switchport connected to FortiGate 'port1' is configured as an 802.1Q Trunk allowing VLAN ID 20."
  },

  // =========================================================================
  // SECTION 0.3: FORTIOS CLI SYNTAX SHIELD & PARSE ERROR PREVENTERS
  // =========================================================================
  {
    id: "syntax-node-check-object",
    title: "Resolving 'node_check_object fail!' & Missing Object Dependencies",
    category: "syntax-shield",
    tags: ["syntax", "node_check_object", "error", "missing object", "dependency", "case sensitive"],
    presets: ["preset-syntax", "preset-policy-templates"],
    whenToUse: "Occurs when you reference an address, service, or interface that does not exist in memory, or has mismatched uppercase/lowercase spelling.",
    template: `# THE ERROR MESSAGE:
# node_check_object fail! for srcaddr H_{{client_ip}}
# Command fail. Return code -61

# ROOT CAUSE 1: Object does not exist yet.
# ROOT CAUSE 2: Letter casing mismatch ("H_Server" vs "H_server").

# STEP 1: Search exact spelling in active address database:
get firewall address | grep -i "{{client_ip}}"

# STEP 2: If missing, create it FIRST before referencing in policy:
config firewall address
  edit "H_{{client_ip}}"
    set subnet {{client_ip}} 255.255.255.255
    set comment "Workstation host"
  next
end

# STEP 3: Now apply to the policy without error:
config firewall policy
  edit 0
    set name "Allow_{{client_ip}}"
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat enable
  next
end`,
    tip: "FortiOS CLI is strictly CASE-SENSITIVE! 'Host1' and 'host1' are two completely different objects in FortiOS."
  },
  {
    id: "syntax-parse-error-quotes",
    title: "Resolving 'command parse error before ...' (Double Quotes & Spaces vs Commas)",
    category: "syntax-shield",
    tags: ["syntax", "parse error", "quotes", "comma", "spaces", "delimiter"],
    presets: ["preset-syntax"],
    whenToUse: "Occurs when setting values with spaces, hyphens, or special characters without enclosing them in quotes, or using commas instead of spaces.",
    template: `# ERROR 1: UNQUOTED STRING WITH SPACES
# set name Office Internet Access ──> FAILS with: command parse error before 'Internet'
# FIX: Always wrap names in double quotes:
set name "Office Internet Access"               # [CORRECT]

# ERROR 2: USING COMMAS TO SEPARATE MULTI-VALUE ITEMS
# set service HTTP, HTTPS, DNS ──> FAILS with: node_check_object fail! for service HTTP,
# FIX: Separate with spaces and individual quotes:
set service "HTTP" "HTTPS" "DNS"                # [CORRECT]

# ERROR 3: MULTIPLE INTERFACES (COMMAS)
# set srcintf port1, port2 ──> FAILS
# FIX:
set srcintf "port1" "port2"                     # [CORRECT]

# ERROR 4: SUBNET MASK NOTATION (CIDR vs DOTTED DECIMAL)
# set subnet 192.168.1.0/24 ──> FAILS in older versions or address objects
# FIX:
set subnet 192.168.1.0 255.255.255.0            # [CORRECT - Universally Supported]`,
    tip: "Universal Best Practice: Wrap every single object name, interface name, and comment in double quotes."
  },
  {
    id: "syntax-central-snat",
    title: "Resolving 'attribute set fail for nat' (Central SNAT Conflict)",
    category: "syntax-shield",
    tags: ["syntax", "central-nat", "snat", "attribute set fail", "nat error"],
    presets: ["preset-syntax", "preset-policy-templates"],
    whenToUse: "Occurs when attempting to type 'set nat enable' inside 'config firewall policy' while Central SNAT is enabled on the FortiGate.",
    template: `# THE ERROR MESSAGE:
# FGT (policy) # set nat enable
# attribute set fail for nat
# Command fail. Return code -1

# STEP 1: Check if Central SNAT is enabled globally:
get system settings | grep central-nat

# IF OUTPUT SHOWS: "central-nat: enable"
# -------------------------------------------------------------
# RESOLUTION: Do NOT set NAT inside the firewall policy.
# Leave policy NAT untouched, and define NAT under central-snat-map:
# -------------------------------------------------------------
# 1. Create Firewall Policy without 'set nat':
config firewall policy
  edit 0
    set name "Policy_Using_Central_SNAT"
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
  next
end

# 2. Configure Central SNAT Map for outbound translation:
config firewall central-snat-map
  edit 0
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set orig-addr "H_{{client_ip}}"
    set dst-addr "all"
    set nat-ippool "wan1"                       # Or specify custom IP Pool
  next
end`,
    tip: "Central SNAT decouples routing policy from NAT policy. Never try to force 'set nat enable' when Central SNAT is active."
  },
  {
    id: "syntax-os-differences",
    title: "FortiOS Cross-Version Syntax Rules (v6.4 vs v7.0 vs v7.2/v7.4/v7.6)",
    category: "syntax-shield",
    tags: ["syntax", "versions", "os", "utm-status", "ngfw", "7.0", "7.2", "7.4"],
    presets: ["preset-syntax"],
    whenToUse: "Reference this card when moving between different FortiOS firmware versions to avoid command deprecation errors.",
    template: `# -------------------------------------------------------------
# 1. UTM / SECURITY PROFILE ACTIVATION
# -------------------------------------------------------------
# In FortiOS 6.4 & 7.0: 'utm-status enable' was MANDATORY:
set utm-status enable                           # Required in v6.4/7.0
set av-profile "default"

# In FortiOS 7.2, 7.4, 7.6: 'utm-status' is DEPRECATED/AUTOMATIC:
# Typing 'set utm-status enable' gives: 'unknown command'
# Simply set profiles directly:
set ssl-ssh-profile "certificate-inspection"
set av-profile "default"
set webfilter-profile "default"

# -------------------------------------------------------------
# 2. POLICY TABLE IN NGFW POLICY-BASED MODE
# -------------------------------------------------------------
# Check current VDOM policy mode:
get system settings | grep -i "policy-mode"

# Profile-Based Mode (Standard 99%):
config firewall policy

# Policy-Based Mode (NGFW Mode):
config firewall security-policy

# -------------------------------------------------------------
# 3. INTERFACE IP ACCESS (ALLOWACCESS)
# -------------------------------------------------------------
# Space-separated list across all versions:
config system interface
  edit "{{interface}}"
    set allowaccess ping https ssh fgfm fabric  # Universal syntax
  next
end`,
    tip: "If a command that worked in FortiOS 6.4 gives 'unknown command' in 7.4, check whether the parameter was simplified or made automatic."
  },
  {
    id: "syntax-edit-zero-safety",
    title: "Preventing Overwrite Disasters: When to Use 'edit 0' vs Explicit ID",
    category: "syntax-shield",
    tags: ["syntax", "edit 0", "overwrite", "safety", "policy id"],
    presets: ["preset-syntax", "preset-cli-ops"],
    whenToUse: "Understand how FortiOS assigns IDs to avoid accidentally overwriting existing production firewall rules or routes.",
    template: `# -------------------------------------------------------------
# RULE 1: ALWAYS USE 'edit 0' TO CREATE A NEW OBJECT OR POLICY
# -------------------------------------------------------------
config firewall policy
  edit 0                                        # Safe: FortiOS finds next free integer (e.g. 51)
    set name "New_Safe_Rule"
    # ...
  next
end

# -------------------------------------------------------------
# DANGER: IF YOU TYPE 'edit 1' AND POLICY 1 ALREADY EXISTS:
# -------------------------------------------------------------
# YOU WILL OVERWRITE POLICY 1!
# Always inspect existing policies before using an explicit ID:
show firewall policy

# -------------------------------------------------------------
# RULE 2: ONLY USE EXPLICIT ID WHEN INTENTIONALLY MODIFYING:
# -------------------------------------------------------------
# View policy 5 before modifying:
show firewall policy 5

# Modify only the specific parameter:
config firewall policy
  edit 5
    set logtraffic all                          # Updates policy 5 without touching other settings
  next
end`,
    tip: "'edit 0' is the safest command in FortiOS CLI. It guarantees you will never accidentally overwrite an existing rule or object."
  },
  {
    id: "syntax-case-sensitivity",
    title: "FortiOS CLI Case Sensitivity & Production Naming Standards",
    category: "syntax-shield",
    tags: ["syntax", "case sensitive", "naming convention", "standards"],
    presets: ["preset-syntax", "preset-object-templates"],
    whenToUse: "Prevent hard-to-spot typos in CLI commands by following standardized naming prefixes.",
    template: `# FORTIOS OBJECT NAMES ARE 100% CASE-SENSITIVE:
# "Server_A" != "server_a" != "SERVER_A"
# If you create "Server_A" and type:
# set srcaddr "server_a" ──> FAILS: node_check_object fail!

# -------------------------------------------------------------
# RECOMMENDED PRODUCTION NAMING CONVENTION (UPPERCASE PREFIXES):
# -------------------------------------------------------------
# 1. Single Hosts (/32):
edit "H_{{client_ip}}"                          # e.g. H_192.168.1.100 or H_Web01

# 2. Entire Subnets (/24, /16):
edit "NET_Office_LAN"                           # e.g. NET_192.168.1.0_24

# 3. IP Ranges:
edit "RNG_Static_Printers"                      # e.g. RNG_192.168.1.50_80

# 4. FQDN Domain Names:
edit "FQDN_Office365"                           # e.g. FQDN_portal.office.com

# 5. Address Groups:
edit "GRP_Finance_PCs"                          # e.g. GRP_Engineering_Subnets

# 6. Custom Services:
edit "SVC_ERP_{{port}}"                         # e.g. SVC_Custom_8080

# 7. Virtual IPs (Port Forwarding):
edit "VIP_Public_{{port}}"                      # e.g. VIP_WebServer_443

# 8. IPsec Tunnels:
edit "VPN_HQ_to_Branch"                         # Clear site-to-site identifier`,
    tip: "Using standardized uppercase prefixes (H_, NET_, SVC_, GRP_, VIP_) eliminates case mismatch errors and makes logs instantly readable."
  },

  // =========================================================================
  // SECTION 0.4: INTERFACE CREATION & TRUNKING (PHYSICAL, VLAN, LACP, LOOPBACK)
  // =========================================================================
  {
    id: "interface-physical-config",
    title: "Physical Interface Setup: Static IP, Speed, MTU & Management Access",
    category: "interfaces",
    tags: ["interfaces", "physical", "port", "ip", "allowaccess", "speed", "mtu"],
    presets: ["preset-interfaces"],
    whenToUse: "Configure a physical FortiGate port for static IP, administrative protocols (PING, HTTPS, SSH), speed negotiation, and MTU.",
    template: `config system interface
  edit "{{interface}}"                         # [CHANGE]: e.g. "port1", "internal", "wan1"
    set vdom "root"                            # [KEEP]: Root VDOM
    set mode static                            # [KEEP]: Static IP (use 'dhcp' for DHCP WAN)
    set ip {{fortigate_ip}} 255.255.255.0       # [CHANGE]: Interface IP & subnet mask
    set allowaccess ping https ssh fgfm fabric # [CHANGE]: Permitted management protocols
    set status up                              # [KEEP]: Enable port ('set status down' disables)
    set speed auto                             # [KEEP]: Auto-negotiate 1G/10G/25G speed
    set mtu-override disable                   # [KEEP]: Use standard 1500 byte MTU
    set description "Main Office Network Port" # [CHANGE]: Description
  next
end`,
    tip: "Always include 'ping' and 'ssh' or 'https' under 'set allowaccess', otherwise you will be locked out of management access on that interface."
  },
  {
    id: "interface-vlan-trunk",
    title: "802.1Q VLAN Sub-Interface on Switch Trunk Port",
    category: "interfaces",
    tags: ["interfaces", "vlan", "trunk", "802.1q", "subinterface", "tag"],
    presets: ["preset-interfaces", "preset-policy-templates"],
    whenToUse: "Create a tagged 802.1Q VLAN sub-interface on a physical port connected to a core or distribution switch trunk port.",
    template: `config system interface
  edit "VLAN20_Guest"                          # [CHANGE]: Unique name for this VLAN interface
    set vdom "root"                            # [KEEP]: Root VDOM
    set ip 192.168.20.1 255.255.255.0          # [CHANGE]: Gateway IP for this VLAN subnet
    set allowaccess ping https ssh             # [CHANGE]: Allowed management services
    set interface "{{interface}}"              # [CHANGE]: Physical parent trunk port (e.g. "port1")
    set vlanid 20                              # [CHANGE]: 802.1Q VLAN Tag ID (1 to 4094)
    set description "Guest WiFi VLAN"          # [CHANGE]: Description
  next
end

# Check status of new VLAN interface:
get system interface "VLAN20_Guest"`,
    tip: "Verify that the upstream switch port is configured as an 802.1Q trunk allowing the specified VLAN ID."
  },
  {
    id: "interface-lacp-aggregate",
    title: "802.3ad LACP Link Aggregation (Dual-Port Bond with Redundancy)",
    category: "interfaces",
    tags: ["interfaces", "lacp", "aggregate", "bond", "trunk", "802.3ad", "redundancy"],
    presets: ["preset-interfaces"],
    whenToUse: "Bond two or more physical ports into a single logical channel for 2x/4x bandwidth and instant hardware failover.",
    template: `# STEP 1: Verify ports have NO existing IP or policy references:
diagnose sys checkused system.interface.name "port3"
diagnose sys checkused system.interface.name "port4"

# STEP 2: Create LACP 802.3ad Aggregate:
config system interface
  edit "AGG_Core_Trunk"                        # [CHANGE]: Aggregate interface name
    set vdom "root"                            # [KEEP]: Root VDOM
    set type aggregate                         # [KEEP]: 802.3ad LACP aggregate
    set member "port3" "port4"                 # [CHANGE]: Physical ports to bond together
    set lacp-mode active                       # [KEEP]: Active LACP negotiation
    set ip 10.10.10.1 255.255.255.0            # [CHANGE]: IP address of bonded channel
    set allowaccess ping https ssh             # [CHANGE]: Allowed management services
    set description "Dual-port LACP trunk"     # [CHANGE]: Description
  next
end

# STEP 3: Verify LACP negotiation state:
diagnose netlink aggregate name AGG_Core_Trunk`,
    tip: "Ports must be cleared of all IP addresses and policy references before they can be added to an LACP aggregate."
  },
  {
    id: "interface-loopback",
    title: "Loopback Interface: Dedicated Management & BGP Router-ID (Always UP)",
    category: "interfaces",
    tags: ["interfaces", "loopback", "router-id", "management", "always up"],
    presets: ["preset-interfaces", "preset-routing"],
    whenToUse: "Create a virtual loopback interface that never goes down. Essential for OSPF/BGP router identification and out-of-band management.",
    template: `config system interface
  edit "LOOPBACK_MGMT"                         # [CHANGE]: Loopback name
    set vdom "root"                            # [KEEP]: Root VDOM
    set type loopback                          # [KEEP]: Virtual loopback
    set ip 10.255.255.1 255.255.255.255        # [CHANGE]: Dedicated /32 IP
    set allowaccess ping https ssh             # [KEEP]: Management services
    set description "Router-ID and Out-of-Band"# [CHANGE]: Description
  next
end

# Verify loopback interface status:
get system interface "LOOPBACK_MGMT"`,
    tip: "Because loopback interfaces never experience physical link-down states, they provide the most reliable target for monitoring and VPN terminations."
  },

  // =========================================================================
  // SECTION 0.5: SD-WAN CLI ARCHITECTURE (DUAL ISP, VPN OVERLAY, PERFORMANCE SLA)
  // =========================================================================
  {
    id: "sdwan-full-setup",
    title: "Complete SD-WAN Deployment: Dual ISPs, Zones, Health-Check SLA & Steering",
    category: "sdwan",
    tags: ["sdwan", "dual isp", "failover", "sla", "health-check", "zone", "members", "steering"],
    presets: ["preset-sdwan", "preset-route-templates"],
    whenToUse: "Deploy enterprise SD-WAN with dual ISP failover, real-time performance probing, and automatic failover when latency, jitter, or loss exceeds SLA.",
    template: `# -------------------------------------------------------------
# STEP 1: CREATE SD-WAN LOGICAL ZONES
# -------------------------------------------------------------
config system sdwan
  config zone
    edit "Underlay_Internet"                   # [CHANGE]: Zone for Internet ISPs
    next
    edit "Overlay_VPN"                         # [CHANGE]: Zone for site-to-site VPNs
    next
  end
end

# -------------------------------------------------------------
# STEP 2: ADD MEMBERS (WAN PORTS & TIGHT GATEWAYS)
# -------------------------------------------------------------
config system sdwan
  config members
    edit 1                                     # Member 1 (Primary ISP)
      set interface "wan1"                     # [CHANGE]: Primary WAN port
      set zone "Underlay_Internet"             # [KEEP]: Assigned zone
      set gateway {{fortigate_ip}}             # [CHANGE]: Primary ISP gateway IP
    next
    edit 2                                     # Member 2 (Secondary ISP)
      set interface "wan2"                     # [CHANGE]: Secondary WAN port
      set zone "Underlay_Internet"             # [KEEP]: Assigned zone
      set gateway {{peer_ip}}                  # [CHANGE]: Secondary ISP gateway IP
    next
  end
end

# -------------------------------------------------------------
# STEP 3: CONFIGURE PERFORMANCE SLA (REAL-TIME HEALTH-CHECK)
# -------------------------------------------------------------
config system sdwan
  config health-check
    edit "SLA_DNS_Google"
      set server "8.8.8.8" "1.1.1.1"           # [KEEP]: Probe targets
      set protocol ping                        # [KEEP]: Ping probe
      set interval 1000                        # [KEEP]: Probe every 1000ms (1s)
      set failtime 3                           # [KEEP]: 3 drops = link degraded
      set recoverytime 5                       # [KEEP]: 5 replies = link recovered
      set members 1 2                          # [KEEP]: Tests Member 1 and Member 2
      config sla
        edit 1
          set latency-threshold 50             # [CHANGE]: Max 50ms latency
          set jitter-threshold 10              # [CHANGE]: Max 10ms jitter
          set packetloss-threshold 2           # [CHANGE]: Max 2% packet loss
        next
      end
    next
  end
end

# -------------------------------------------------------------
# STEP 4: CONFIGURE SD-WAN STEERING RULES
# -------------------------------------------------------------
config system sdwan
  config service
    edit 1
      set name "Steer_Internet_Traffic"
      set mode priority                        # [KEEP]: Priority failover mode
      set dst "all"                            # [KEEP]: All internet traffic
      set health-check "SLA_DNS_Google"        # [KEEP]: Link to SLA check
      set priority-members 1 2                 # [KEEP]: Prefer Member 1; failover to Member 2
    next
  end
end

# -------------------------------------------------------------
# STEP 5: DEFAULT ROUTE POINTING TO SD-WAN ZONE
# -------------------------------------------------------------
config router static
  edit 0
    set dst 0.0.0.0 0.0.0.0                    # [KEEP]: Default route
    set sdwan-zone "Underlay_Internet"         # [CRITICAL]: Route to SD-WAN zone (FortiOS 7.x)
    # FortiOS 6.4/7.0: set device "sdwan"
    set comment "Default route via SD-WAN"
  next
end

# -------------------------------------------------------------
# STEP 6: FIREWALL POLICY ALLOWING TRAFFIC VIA SD-WAN
# -------------------------------------------------------------
config firewall policy
  edit 0
    set name "LAN_to_SDWAN_Internet"
    set srcintf "{{interface}}"                # [CHANGE]: Ingress LAN port
    set dstintf "Underlay_Internet"            # [CRITICAL]: Egress is SD-WAN Zone!
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat enable                             # [CRITICAL]: Must enable NAT for Internet
    set logtraffic all
  next
end`,
    tip: "In FortiOS 7.x, the firewall policy points to the SD-WAN Zone ('Underlay_Internet'), which decouples firewall rules from physical WAN port changes."
  },
  {
    id: "sdwan-vpn-overlay",
    title: "SD-WAN VPN Overlay: Dual Hub-and-Spoke IPsec with Performance SLA",
    category: "sdwan",
    tags: ["sdwan", "vpn", "overlay", "sla", "ipsec", "dual hub"],
    presets: ["preset-sdwan", "preset-vpn-down"],
    whenToUse: "Route corporate branch traffic across primary and secondary IPsec tunnels using SD-WAN quality metrics (switches tunnels automatically if jitter or packet loss spikes).",
    template: `# -------------------------------------------------------------
# STEP 1: ADD IPSEC TUNNELS TO SD-WAN OVERLAY ZONE
# -------------------------------------------------------------
config system sdwan
  config members
    edit 3                                     # Member 3: Primary DC Tunnel
      set interface "{{tunnel_name}}"          # [CHANGE]: Primary tunnel name
      set zone "Overlay_VPN"                   # [KEEP]: VPN Overlay zone
    next
    edit 4                                     # Member 4: Backup DC Tunnel
      set interface "{{tunnel_name}}_Backup"   # [CHANGE]: Secondary tunnel name
      set zone "Overlay_VPN"
    next
  end
end

# -------------------------------------------------------------
# STEP 2: CONFIGURE VPN SLA HEALTH-CHECK (PING DC INTERNAL IP)
# -------------------------------------------------------------
config system sdwan
  config health-check
    edit "SLA_DataCenter_Core"
      set server "{{server_ip}}"               # [CHANGE]: Target core server in Data Center
      set protocol ping
      set interval 1000
      set failtime 3
      set recoverytime 5
      set members 3 4                          # [KEEP]: Tests Primary & Backup tunnels
      config sla
        edit 1
          set latency-threshold 30             # Max 30ms latency to DC
          set jitter-threshold 5               # Max 5ms jitter
          set packetloss-threshold 1           # Max 1% loss
        next
      end
    next
  end
end

# -------------------------------------------------------------
# STEP 3: SD-WAN STEERING RULE FOR CORPORATE DATA
# -------------------------------------------------------------
config system sdwan
  config service
    edit 2
      set name "Steer_Corporate_to_DC"
      set mode priority
      set dst "{{server_ip}}"                  # [CHANGE]: Remote Data Center subnet
      set health-check "SLA_DataCenter_Core"
      set priority-members 3 4                 # Prefer Primary tunnel (3); failover to Backup (4)
    next
  end
end`,
    tip: "For VPN overlay health-checks, always probe an internal IP inside the remote Data Center rather than public IPs."
  },
  {
    id: "sdwan-diagnostics",
    title: "Real-Time SD-WAN CLI Monitoring: SLA Metrics, Quality Scores & Member Selection",
    category: "sdwan",
    tags: ["sdwan", "diagnostics", "health-check", "sla metrics", "member status", "cli monitor"],
    presets: ["preset-sdwan", "preset-cli-ops"],
    whenToUse: "Verify which ISP link is currently chosen by SD-WAN rules and view live latency, jitter, packet loss, and bandwidth consumption in CLI.",
    template: `# 1. View live latency, jitter, packet loss, and SLA state for all links:
diagnose sys sdwan health-check

# 2. View which member is currently selected by each SD-WAN rule:
diagnose sys sdwan service

# 3. View packet and byte traffic counters across all SD-WAN members:
diagnose sys sdwan member

# 4. View active FIB routes selected by SD-WAN:
get router info routing-table all | grep -i "sdwan"`,
    tip: "If a member shows 'state: dead' in 'diagnose sys sdwan health-check', the gateway or probe target is not answering pings."
  },

  // =========================================================================
  // SECTION 0.6: REFERENCE MIGRATION (HOW TO MOVE REFERENCES WITHOUT LOSING CONFIG)
  // =========================================================================
  {
    id: "migration-sdwan-zero-loss",
    title: "Zero-Loss Reference Migration: Moving WAN Interface into SD-WAN Without Policy Deletion",
    category: "migration",
    tags: ["migration", "checkused", "zero loss", "sdwan", "move reference", "swap", "no downtime"],
    presets: ["preset-migration", "preset-sdwan", "preset-cli-ops"],
    whenToUse: "When you want to add an active interface (e.g. wan1) into an SD-WAN zone, but FortiOS blocks you with 'entry is used by another entry'. This procedure swaps all references directly in CLI with zero downtime and zero deleted policies.",
    template: `# =============================================================
# ZERO-LOSS MIGRATION: MOVING WAN1 INTO SD-WAN WITHOUT DELETING RULES
# =============================================================

# STEP 1: Discover all references currently bound to wan1:
diagnose sys checkused system.interface.name "wan1"
# [Note down all Policy IDs, Static Route IDs, and VIPs listed]

# STEP 2: Create target SD-WAN zone first (empty, so it exists in memory):
config system sdwan
  config zone
    edit "Underlay_Internet"
    next
  end
end

# STEP 3: Swap policy destination interfaces from wan1 to SD-WAN zone:
# (All rules, source IPs, security profiles, NAT, and comments are PRESERVED!)
config firewall policy
  edit 1                                       # [CHANGE]: Policy ID from Step 1
    set dstintf "Underlay_Internet"            # Replaces wan1 with SD-WAN zone
  next
  edit 4                                       # [CHANGE]: Next policy ID from Step 1
    set dstintf "Underlay_Internet"
  next
end

# STEP 4: Swap or re-point static route 1 to SD-WAN zone:
config router static
  edit 1                                       # [CHANGE]: Default route ID from Step 1
    unset device                               # Removes direct wan1 binding
    set sdwan-zone "Underlay_Internet"         # Points to SD-WAN zone
  next
end

# STEP 5: Verify that wan1 has ZERO remaining references:
diagnose sys checkused system.interface.name "wan1"
# [CLI must now report: "No reference found for system.interface.name wan1"]

# STEP 6: Add wan1 into SD-WAN members cleanly without error:
config system sdwan
  config members
    edit 1
      set interface "wan1"
      set zone "Underlay_Internet"
      set gateway {{fortigate_ip}}             # [CHANGE]: ISP Gateway IP
    next
  end
end

# STEP 7: Verify migration success:
diagnose sys sdwan member`,
    tip: "Never delete a firewall policy to free an interface. Swapping 'set dstintf' directly preserves all security settings, rules, and statistics."
  },
  {
    id: "migration-lacp-zero-loss",
    title: "Zero-Loss Interface Migration: Moving Physical Ports into an 802.3ad LACP Aggregate Bond",
    category: "migration",
    tags: ["migration", "lacp", "aggregate", "zero loss", "move reference", "bond"],
    presets: ["preset-migration", "preset-interfaces"],
    whenToUse: "When upgrading single uplink ports into a redundant LACP 802.3ad aggregate trunk without re-creating all VLANs, DHCP scopes, and firewall rules from scratch.",
    template: `# STEP 1: Find all references bound to port3 and port4:
diagnose sys checkused system.interface.name "port3"
diagnose sys checkused system.interface.name "port4"

# STEP 2: If port3 has VLAN sub-interfaces, move them to the aggregate:
# 1. Create the aggregate trunk first with port4:
config system interface
  edit "AGG_Core_Trunk"
    set vdom "root"
    set type aggregate
    set member "port4"                         # Initially add port4
    set lacp-mode active
  next
end

# 2. Swap parent interface on VLAN sub-interfaces:
config system interface
  edit "VLAN20_Guest"
    set interface "AGG_Core_Trunk"             # Repoint parent from port3 to aggregate!
  next
end

# 3. Now that port3 is free, add port3 to the aggregate:
config system interface
  edit "AGG_Core_Trunk"
    set member "port3" "port4"                 # Both ports now bonded!
  next
end

# STEP 3: Verify LACP bonding status:
diagnose netlink aggregate name AGG_Core_Trunk`,
    tip: "Swapping the parent interface of a VLAN sub-interface ('set interface') preserves the VLAN ID, IP address, DHCP scope, and all firewall policies automatically."
  },

  // =========================================================================
  // SECTION 0.7: POLICY-BASED ROUTING (PBR) VS ROUTING TABLE
  // =========================================================================
  {
    id: "pbr-traffic-steering",
    title: "Policy-Based Routing (PBR): Force Specific Client/Port out Secondary WAN",
    category: "pbr",
    tags: ["pbr", "policy route", "routing", "steering", "secondary isp", "precedence"],
    presets: ["preset-pbr", "preset-route-templates"],
    whenToUse: "Override normal routing table lookup to steer specific users, subnets, or application ports out a secondary ISP or dedicated link (e.g. VIP executive PC or backup replication).",
    template: `config router policy
  edit 0                                       # [KEEP]: Auto-assigns ID
    set input-device "{{interface}}"           # [CHANGE]: Ingress port where client connects (e.g. "port1")
    set src {{client_ip}} 255.255.255.255      # [CHANGE]: Client IP to redirect (or subnet)
    set dst 0.0.0.0 0.0.0.0                    # [KEEP]: All destinations
    set protocol 6                             # [KEEP]: 6 = TCP (17 = UDP, 0 = ANY)
    set start-port {{port}}                    # [CHANGE]: Application port range
    set end-port {{port}}
    set gateway {{peer_ip}}                    # [CHANGE]: Secondary ISP router gateway IP
    set output-device "wan2"                   # [CHANGE]: Secondary WAN egress interface
    set comments "Force HTTPS traffic out WAN2"# [CHANGE]: Description
  next
end

# Verify policy route entry:
show router policy`,
    tip: "Kernel Routing Precedence: Policy Routes (PBR) evaluate BEFORE SD-WAN rules, and SD-WAN rules evaluate BEFORE the standard routing table."
  },
  {
    id: "pbr-reorder-fallback",
    title: "PBR Priority & Reordering: Move Rules & Inspect Automatic Gateway Fallback",
    category: "pbr",
    tags: ["pbr", "reorder", "move", "priority", "fallback", "failover"],
    presets: ["preset-pbr", "preset-cli-ops"],
    whenToUse: "Reorder Policy Routes top-to-bottom and verify fallback behavior when the next-hop gateway goes down.",
    template: `# 1. Display all policy routes and their ID numbers:
show router policy

# 2. Move policy route ID 3 BEFORE policy route ID 1 (higher priority):
config router policy
  move 3 before 1
end

# 3. Verify gateway reachability check for PBR:
# (If gateway becomes unreachable, FortiOS automatically falls back to FIB table)
get router info routing-table details {{peer_ip}}`,
    tip: "Fail-Safe: If the next-hop gateway specified in a PBR rule becomes unreachable, FortiOS automatically bypasses the rule and falls back to the active routing table."
  },

  // =========================================================================
  // SECTION 0.8: FULL VPN DEPLOYMENT (IPSEC & SSL-VPN)
  // =========================================================================
  {
    id: "vpn-ipsec-full-deployment",
    title: "Route-Based Site-to-Site IPsec VPN (Complete IKEv2 CLI Deployment)",
    category: "ipsec",
    tags: ["vpn", "ipsec", "ikev2", "phase 1", "phase 2", "site to site", "tunnel", "full setup"],
    presets: ["preset-vpn-down", "preset-workflow"],
    whenToUse: "Complete end-to-end route-based IPsec VPN deployment via CLI: Phase 1, Phase 2, Static Route via tunnel, and dual no-NAT firewall policies.",
    template: `# -------------------------------------------------------------
# STEP 1: PHASE 1 INTERFACE
# -------------------------------------------------------------
config vpn ipsec phase1-interface
  edit "{{tunnel_name}}"
    set interface "wan1"                       # [CHANGE]: WAN port connected to ISP
    set ike-version 2                          # [KEEP]: IKEv2 standard
    set peertype any                           # [KEEP]: Any peer type
    set net-device disable                     # [KEEP]: Route-based tunnel
    set proposal aes256-sha256 aes128-sha256   # [KEEP]: Encryption & hash
    set dpd on-idle                            # [KEEP]: Dead Peer Detection
    set dhgrp 14 5                             # [KEEP]: Diffie-Hellman groups
    set remote-gw {{peer_ip}}                  # [CHANGE]: Remote firewall public IP
    set psksecret "YourSecurePskSecret123!"    # [CHANGE]: Pre-shared key password
  next
end

# -------------------------------------------------------------
# STEP 2: PHASE 2 INTERFACE
# -------------------------------------------------------------
config vpn ipsec phase2-interface
  edit "{{tunnel_name}}_p2"
    set phase1name "{{tunnel_name}}"           # [KEEP]: Binds to Phase 1 created above
    set proposal aes256-sha256 aes128-sha256   # [KEEP]: Phase 2 encryption
    set dhgrp 14 5                             # [KEEP]: DH group
    set auto-negotiate enable                  # [KEEP]: Keep tunnel active 24/7
    set src-subnet 192.168.1.0 255.255.255.0   # [CHANGE]: Local LAN subnet
    set dst-subnet {{server_ip}} 255.255.255.0 # [CHANGE]: Remote office subnet
  next
end

# -------------------------------------------------------------
# STEP 3: ROUTE TO REMOTE SUBNET VIA IPSEC TUNNEL
# -------------------------------------------------------------
config router static
  edit 0
    set dst {{server_ip}} 255.255.255.0        # [CHANGE]: Remote office subnet
    set device "{{tunnel_name}}"               # [KEEP]: Virtual IPsec interface
    set comment "Route across IPsec VPN"
  next
end

# -------------------------------------------------------------
# STEP 4: DUAL FIREWALL POLICIES (OUTBOUND & INBOUND, NO-NAT)
# -------------------------------------------------------------
config firewall policy
  # Outbound: LAN to Remote Office
  edit 0
    set name "LAN_to_Remote_Office"
    set srcintf "{{interface}}"
    set dstintf "{{tunnel_name}}"
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable                            # [CRITICAL]: NEVER enable NAT across IPsec!
    set logtraffic all
  next
  # Inbound: Remote Office to LAN
  edit 0
    set name "Remote_Office_to_LAN"
    set srcintf "{{tunnel_name}}"
    set dstintf "{{interface}}"
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat disable                            # [CRITICAL]: NEVER enable NAT across IPsec!
    set logtraffic all
  next
end

# -------------------------------------------------------------
# STEP 5: BRING UP TUNNEL & TEST
# -------------------------------------------------------------
diagnose vpn ike restart {{tunnel_name}}
get vpn ipsec tunnel summary`,
    tip: "Crucial Rule: NAT must remain disabled on both VPN policies so that packets retain their true internal IP addresses."
  },
  {
    id: "vpn-sslvpn-full-deployment",
    title: "Remote Access SSL-VPN: Portal, Daemon Settings, User Group & Access Policy",
    category: "sslvpn",
    tags: ["vpn", "sslvpn", "remote access", "portal", "tunnel-mode", "user group", "full setup"],
    presets: ["preset-sslvpn", "preset-workflow"],
    whenToUse: "Deploy client SSL-VPN (FortiClient) from scratch via CLI with identity-based firewall policy.",
    template: `# -------------------------------------------------------------
# STEP 1: CREATE LOCAL USER & USER GROUP
# -------------------------------------------------------------
config user local
  edit "{{username}}"                          # [CHANGE]: SSL VPN username
    set type password
    set passwd "UserComplexPass123!"           # [CHANGE]: User password
  next
end

config user group
  edit "GRP_SSLVPN_RemoteUsers"                # [CHANGE]: Group name
    set member "{{username}}"                  # [KEEP]: Add user to group
  next
end

# -------------------------------------------------------------
# STEP 2: CREATE SSL-VPN WEB PORTAL (FULL TUNNEL MODE)
# -------------------------------------------------------------
config vpn ssl web portal
  edit "Full_Access_Portal"
    set tunnel-mode enable                     # [KEEP]: FortiClient tunnel mode
    set ipv6-tunnel-mode disable
    set ip-pools "SSLVPN_TUNNEL_ADDR1"         # [KEEP]: Default FortiOS SSL-VPN IP pool
  next
end

# -------------------------------------------------------------
# STEP 3: CONFIGURE SSL-VPN GLOBAL DAEMON SETTINGS
# -------------------------------------------------------------
config vpn ssl settings
  set servercert "Fortinet_Factory"            # [CHANGE]: SSL Certificate
  set tunnel-ip-pools "SSLVPN_TUNNEL_ADDR1"    # [KEEP]: IP pool
  set source-interface "wan1"                  # [CHANGE]: Egress WAN port
  set source-port 10443                        # [CHANGE]: Non-standard port to avoid conflicts
  set default-portal "Full_Access_Portal"
  config authentication-rule
    edit 1
      set groups "GRP_SSLVPN_RemoteUsers"
      set portal "Full_Access_Portal"
    next
  end
end

# -------------------------------------------------------------
# STEP 4: FIREWALL POLICY ALLOWING SSL-VPN USERS INTO LAN
# -------------------------------------------------------------
config firewall policy
  edit 0
    set name "SSLVPN_to_Office_LAN"
    set srcintf "ssl.root"                     # [KEEP]: FortiOS virtual SSL interface
    set dstintf "{{interface}}"                # [CHANGE]: Internal LAN port
    set srcaddr "all"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set groups "GRP_SSLVPN_RemoteUsers"        # [CRITICAL]: Identity check on rule
    set nat enable                             # [KEEP]: NATs to FortiGate LAN IP
    set logtraffic all
  next
end

# Check connected SSL-VPN users:
get vpn ssl monitor`,
    tip: "Remember that 'ssl.root' is the virtual source interface for all SSL-VPN connections, and the firewall policy must specify the authorized user group under 'set groups'."
  },

  // =========================================================================
  // SECTION 1: ERROR & LOG RESOLVER (DEEP-DIVE FIND & FIX)
  // =========================================================================
  {
    id: "log-err-denied-policy-0",
    title: "Error: \"Denied by policy 0, drop\" (Implicit Deny)",
    category: "error-logs",
    tags: ["error", "log", "denied by policy 0", "implicit deny", "drop", "firewall policy", "traffic blocked"],
    presets: ["preset-error-logs", "preset-packet-drop"],
    isLogAnalysis: true,
    whenToUse: "Client attempts to connect to server/website, but connection times out immediately. Debug flow reveals packet hits rule 0.",
    diagCmd: `diagnose debug reset
diagnose debug flow filter saddr {{client_ip}}
diagnose debug flow filter daddr {{server_ip}}
diagnose debug flow filter port {{port}}
diagnose debug flow show function-name enable
diagnose debug flow trace start 20
diagnose debug console timestamp enable
diagnose debug enable

# Trigger traffic from client now:

diagnose debug disable
diagnose debug reset`,
    rawLog: `id=20085 trace_id=1 func=print_pkt_detail line=5888 msg="vd-root:0 received a packet(proto=6, {{client_ip}}:54321->{{server_ip}}:{{port}}) from {{interface}}. flag [S], seq 12345678"
id=20085 trace_id=1 func=init_ip_session_common line=6064 msg="allocate a new session-0012abcd, tun_id=0.0.0.0"
id=20085 trace_id=1 func=vf_ip_route_input_common line=2605 msg="find a route: flag=04000000 gw-192.168.1.1 via wan1"
id=20085 trace_id=1 func=resolve_ip_tuple_fast line=5973 msg="Find IPv4 policy (0)"
id=20085 trace_id=1 func=__vf_ip4_route_input line=1234 msg="Denied by policy 0, drop"`,
    criticalNeedle: `Denied by policy 0, drop   [and: Find IPv4 policy (0)]`,
    criticalExplanation: "Policy 0 is the FortiGate built-in Implicit Deny rule at the bottom of the policy list. This log is conclusive proof that NO existing firewall policy matches the incoming interface ({{interface}}), outgoing interface, source IP ({{client_ip}}), destination IP ({{server_ip}}), or destination port ({{port}}).",
    template: `# Create the missing firewall policy to allow this traffic:
config firewall policy
  edit 0
    set name "Allow_{{client_ip}}_to_{{server_ip}}"
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "H_{{server_ip}}"
    set action accept
    set schedule "always"
    set service "HTTPS" "HTTP"
    set nat enable
    set logtraffic all
    set logtraffic-start enable
    set comments "Created to fix Denied by policy 0 drop"
  next
end`,
    tip: "Remember to verify source and destination interfaces in the policy match where the packet enters and exits."
  },
  {
    id: "log-err-rpf-drop",
    title: "Error: \"reverse path check failed, drop\" (RPF / Asymmetric Routing)",
    category: "error-logs",
    tags: ["error", "log", "rpf", "reverse path", "asymmetric", "drop", "routing", "src-check"],
    presets: ["preset-error-logs", "preset-asymmetric"],
    isLogAnalysis: true,
    whenToUse: "Traffic arrives at FortiGate, matches an allowed firewall policy, but is immediately dropped before exiting due to reverse routing asymmetry.",
    diagCmd: `diagnose debug reset
diagnose debug flow filter saddr {{client_ip}}
diagnose debug flow filter daddr {{server_ip}}
diagnose debug flow show function-name enable
diagnose debug flow trace start 20
diagnose debug console timestamp enable
diagnose debug enable

# Trigger traffic now:

diagnose debug disable
diagnose debug reset`,
    rawLog: `id=20085 trace_id=3 func=print_pkt_detail line=5888 msg="vd-root:0 received a packet(proto=6, {{client_ip}}:49201->{{server_ip}}:{{port}}) from {{interface}}. flag [S]"
id=20085 trace_id=3 func=resolve_ip_tuple_fast line=5960 msg="Find IPv4 policy (1)"
id=20085 trace_id=3 func=rpdb_core_esr line=145 msg="reverse path check failed, drop"`,
    criticalNeedle: `reverse path check failed, drop`,
    criticalExplanation: "FortiGate anti-spoofing mechanism (Reverse Path Forwarding) verified where it would route return packets to {{client_ip}}. Because its routing table points to a DIFFERENT interface than {{interface}} (where the packet entered), FortiOS drops the packet as an asymmetric anomaly.",
    template: `# FIX OPTION 1 (Recommended): Add/Fix return route so routing is symmetric
config router static
  edit 0
    set dst {{client_ip}} 255.255.255.255
    set gateway {{fortigate_ip}}
    set device "{{interface}}"
    set comment "Symmetric return route for {{client_ip}}"
  next
end

# FIX OPTION 2: Disable strict RPF check on the ingress interface if asymmetric routing is required
config system interface
  edit "{{interface}}"
    set src-check disable
  next
end`,
    tip: "Run 'get router info routing-table details {{client_ip}}' to see where the FortiGate currently thinks {{client_ip}} lives."
  },
  {
    id: "log-err-no-proposal-chosen",
    title: "Error: \"no proposal chosen\" (IPsec Phase 1/2 Cipher Mismatch)",
    category: "error-logs",
    tags: ["error", "log", "vpn", "ipsec", "no proposal chosen", "phase1", "cipher", "dh", "hash"],
    presets: ["preset-error-logs", "preset-vpn-down"],
    isLogAnalysis: true,
    whenToUse: "Site-to-site IPsec tunnel stays DOWN and will not negotiate Phase 1 or Phase 2 Security Associations.",
    diagCmd: `diagnose debug reset
diagnose vpn ike log-filter clear
diagnose vpn ike log-filter dst-addr4 {{peer_ip}}
diagnose debug app ike -1
diagnose debug console timestamp enable
diagnose debug enable

# Force restart negotiation:
diagnose vpn ike restart {{tunnel_name}}

# Turn off:
diagnose debug disable
diagnose debug reset`,
    rawLog: `ike 0:{{tunnel_name}}:12345: incoming proposal:
ike 0:{{tunnel_name}}:12345: proposal id = 1:
ike 0:{{tunnel_name}}:12345:   protocol = IKE:
ike 0:{{tunnel_name}}:12345:      encapsulation = IKEv2:
ike 0:{{tunnel_name}}:12345:         type=ENCR, val=AES_CBC (key_len = 256)
ike 0:{{tunnel_name}}:12345:         type=INTEG, val=AUTH_HMAC_SHA2_256_128
ike 0:{{tunnel_name}}:12345:         type=DH, val=MODP_2048 (Group 14)
ike 0:{{tunnel_name}}:12345: no proposal chosen
ike 0:{{tunnel_name}}:12345: negotiation failure`,
    criticalNeedle: `no proposal chosen`,
    criticalExplanation: "The remote peer {{peer_ip}} proposed encryption algorithms, hash authentication, or Diffie-Hellman groups that are NOT configured on this FortiGate. The parameters must match identically on both firewalls.",
    template: `# Update Phase 1 interface to match remote peer's algorithms:
config vpn ipsec phase1-interface
  edit "{{tunnel_name}}"
    set proposal aes256-sha256 aes128-sha256
    set dhgrp 14 5
    set keylife 86400
  next
end

# Re-trigger negotiation
diagnose vpn ike restart {{tunnel_name}}`,
    tip: "Compare encryption (e.g. AES-256), authentication (e.g. SHA-256), and DH Group (e.g. Group 14 / 2048-bit) on both sides."
  },
  {
    id: "log-err-psk-mismatch",
    title: "Error: \"peer auth failed: preshared key mismatch\" (Bad VPN Password)",
    category: "error-logs",
    tags: ["error", "log", "vpn", "ipsec", "psk", "preshared key", "auth failed", "password"],
    presets: ["preset-error-logs", "preset-vpn-down"],
    isLogAnalysis: true,
    whenToUse: "Phase 1 exchange progresses past proposal exchange, but fails during cryptographic authentication verification.",
    diagCmd: `diagnose debug reset
diagnose vpn ike log-filter dst-addr4 {{peer_ip}}
diagnose debug app ike -1
diagnose debug console timestamp enable
diagnose debug enable

diagnose vpn ike restart {{tunnel_name}}

diagnose debug disable
diagnose debug reset`,
    rawLog: `ike 0:{{tunnel_name}}:12345: sent IKE msg (AUTH): {{peer_ip}}:500
ike 0:{{tunnel_name}}:12345: recv IKE msg (AUTH): {{peer_ip}}:500
ike 0:{{tunnel_name}}:12345: compute payload AUTH
ike 0:{{tunnel_name}}:12345: peer auth failed: preshared key mismatch
ike 0:{{tunnel_name}}:12345: delete SA`,
    criticalNeedle: `peer auth failed: preshared key mismatch   [or: compute payload AUTH failed]`,
    criticalExplanation: "The shared secret password configured under Phase 1 does not match between the two VPN endpoints. Because it is hashed with a nonce, even one wrong character causes an AUTH computation failure.",
    template: `# Reset the Pre-Shared Key on this FortiGate:
config vpn ipsec phase1-interface
  edit "{{tunnel_name}}"
    set psksecret "YourExactComplexPSK123!"
  next
end

# Flush and renegotiate
diagnose vpn ike gateway flush name {{tunnel_name}}`,
    tip: "Check for trailing spaces or special character copy-paste errors when copying the PSK."
  },
  {
    id: "log-err-invalid-id-info",
    title: "Error: \"received notify: INVALID_ID_INFORMATION\" (Phase 2 Subnet Mismatch)",
    category: "error-logs",
    tags: ["error", "log", "vpn", "phase2", "selector", "subnet", "invalid_id_information"],
    presets: ["preset-error-logs", "preset-vpn-down"],
    isLogAnalysis: true,
    whenToUse: "Phase 1 is successfully UP, but Phase 2 fails to establish or only one subnet is accessible.",
    diagCmd: `diagnose debug reset
diagnose vpn ike log-filter dst-addr4 {{peer_ip}}
diagnose debug app ike -1
diagnose debug console timestamp enable
diagnose debug enable

diagnose vpn ike restart {{tunnel_name}}

diagnose debug disable
diagnose debug reset`,
    rawLog: `ike 0:{{tunnel_name}}:12345: Phase 2 selector negotiation:
ike 0:{{tunnel_name}}:12345: local selector: 192.168.1.0/255.255.255.0:0
ike 0:{{tunnel_name}}:12345: remote selector: 10.20.30.0/255.255.255.0:0
ike 0:{{tunnel_name}}:12345: received notify: INVALID_ID_INFORMATION
ike 0:{{tunnel_name}}:12345: failed to negotiate Phase 2`,
    criticalNeedle: `received notify: INVALID_ID_INFORMATION`,
    criticalExplanation: "Phase 2 Proxy IDs (Local & Remote Subnets) do not match the peer's inverted selectors. Your Local Subnet MUST equal the peer's Remote Subnet, and your Remote Subnet MUST equal the peer's Local Subnet.",
    template: `# Correct Phase 2 selector subnets:
config vpn ipsec phase2-interface
  edit "{{tunnel_name}}_p2"
    set phase1name "{{tunnel_name}}"
    set src-subnet 192.168.1.0 255.255.255.0
    set dst-subnet 10.20.30.0 255.255.255.0
    set auto-negotiate enable
  next
end`,
    tip: "If connecting to non-Fortinet firewalls (Cisco ASA, Palo Alto, SonicWall), use /32 for host selectors or ensure 0.0.0.0/0 is set if route-based."
  },
  {
    id: "log-err-conserve-mode",
    title: "Error: \"The system has entered conserve mode\" (RAM Exhaustion)",
    category: "error-logs",
    tags: ["error", "log", "memory", "conserve mode", "ram", "crash", "dropped connection"],
    presets: ["preset-error-logs", "preset-high-cpu"],
    isLogAnalysis: true,
    whenToUse: "FortiGate stops passing proxy-inspected traffic, web filtering drops pages, or admin GUI shows yellow/red conserve mode alert banner.",
    diagCmd: `diagnose hardware sysinfo conserve
get system performance status
diagnose sys top-summary
diagnose sys top 2 10`,
    rawLog: `id=20101 level=alert msg="The system has entered conserve mode."
id=20102 level=warning msg="Total RAM: 1980MB, Used: 1762MB (89%), Free: 218MB (11%)"
id=20103 level=error msg="Proxy worker dropped connection due to memory threshold."
id=20104 msg="Conserve mode red threshold=88%, green threshold=82%"`,
    criticalNeedle: `The system has entered conserve mode.`,
    criticalExplanation: "Memory utilization exceeded 88% (red threshold). To protect OS integrity, FortiOS stops scanning new sessions and either drops proxy connections or fails open depending on configuration.",
    template: `# 1. Free memory immediately by restarting WAD proxy worker (zero firewall reboot needed)
diagnose test application wad 99

# 2. Lower conserve mode impact by tuning session memory retention
config system global
  set tcp-halfclose-timer 30
  set tcp-halfopen-timer 30
  set tcp-timewait-timer 10
end

# 3. Configure AV failopen so traffic isn't dropped during spikes
config system fortiguard
  set antispam-cache-mpercent 20
end`,
    tip: "Restarting WAD (Web Access Daemon) releases leaked proxy RAM safely in production without dropping active static routing or IPsec tunnels."
  },
  {
    id: "log-err-ldap-code-49",
    title: "Error: \"ldap_bind failed, return code: 49\" (SSL VPN Auth Failed)",
    category: "error-logs",
    tags: ["error", "log", "ldap", "radius", "ssl vpn", "return code 49", "auth failed", "active directory"],
    presets: ["preset-error-logs", "preset-ssl-vpn"],
    isLogAnalysis: true,
    whenToUse: "Remote SSL VPN user cannot login via FortiClient; FortiClient reports 'Credential or SSL VPN configuration is wrong (-8)'.",
    diagCmd: `diagnose debug reset
diagnose debug app sslvpn -1
diagnose debug app fnbamd -1
diagnose debug console timestamp enable
diagnose debug enable

# Have user {{username}} attempt login now:

diagnose debug disable
diagnose debug reset`,
    rawLog: `[fnbamd_ldap.c:1234]: authenticate_user '{{username}}'
[fnbamd_ldap.c:1255]: connecting to ldap server {{tftp_ip}}:389
[fnbamd_ldap.c:1290]: ldap_bind failed, return code: 49 (Invalid credentials)
[fnbamd_auth.c:450]: user '{{username}}' authentication failed
[sslvpn:err] ssl_vpn_auth_authenticate_user: invalid username or password`,
    criticalNeedle: `ldap_bind failed, return code: 49 (Invalid credentials)`,
    criticalExplanation: "Active Directory LDAP error code 49 means 'Invalid Credentials'. Either the user entered an incorrect password, user account is disabled/locked out in Windows AD, or FortiGate's service account bind password has expired.",
    template: `# 1. Test LDAP credentials directly from FortiGate CLI:
diagnose test authserver ldap "Corp_AD_LDAP" {{username}} "UserPassword123"

# 2. If the Service Account password changed in Active Directory, update bind:
config user ldap
  edit "Corp_AD_LDAP"
    set password "NewServiceAccountPassword123!"
  next
end`,
    tip: "Sub-code 52e = wrong password; sub-code 532 = password expired; sub-code 533 = account disabled; sub-code 775 = account locked out."
  },
  {
    id: "log-err-asic-bypass",
    title: "Error: \"traffic offloaded to NP6/NP7 ASIC\" (Packets Missing in Trace)",
    category: "error-logs",
    tags: ["error", "log", "asic", "np6", "np7", "offload", "packets missing", "tcpdump"],
    presets: ["preset-error-logs"],
    isLogAnalysis: true,
    whenToUse: "You initiate a packet sniffer or debug flow, see only the first 1-2 TCP handshake packets, and then all subsequent data packets vanish from CLI.",
    diagCmd: `diagnose debug reset
diagnose debug flow filter saddr {{client_ip}}
diagnose debug flow filter daddr {{server_ip}}
diagnose debug flow show function-name enable
diagnose debug flow trace start 10
diagnose debug enable`,
    rawLog: `id=20085 trace_id=1 func=resolve_ip_tuple_fast line=5960 msg="Find IPv4 policy (5)"
id=20085 trace_id=1 func=np6_ip4_offload line=880 msg="traffic offloaded to NP6/NP7 ASIC"
# [ALL SUBSEQUENT PACKETS VANISH FROM CONSOLE OUTPUT]`,
    criticalNeedle: `traffic offloaded to NP6/NP7 ASIC`,
    criticalExplanation: "FortiOS hardware acceleration offloads established flows directly to the network processor silicon (NP6/NP7). Offloaded packets never hit the CPU kernel where sniffer and debug flow listen, making ongoing traffic appear invisible.",
    template: `# Temporarily disable ASIC offload on the policy being troubleshot:
config firewall policy
  edit 5
    set auto-asic-offload disable
  next
end

# Re-run your sniffer or flow trace now to see all packets!
# IMPORTANT: Re-enable when troubleshooting is done for max performance:
# set auto-asic-offload enable`,
    tip: "Remember to re-enable auto-asic-offload after testing to restore multi-gigabit throughput."
  },

  // =========================================================================
  // SECTION 2: CONFIGURATION TEMPLATES (POLICIES, OBJECTS, GROUPS, VIPS)
  // =========================================================================
  {
    id: "tmpl-policy-internet",
    title: "Firewall Policy: Outbound Internet Access (NAT & Security Profiles)",
    category: "policy-templates",
    tags: ["policy", "template", "internet", "nat", "outbound", "create policy"],
    presets: ["preset-policy-templates"],
    whenToUse: "Standard production policy to give internal LAN clients internet access with Source NAT and security inspection.",
    template: `config firewall policy
  edit 0
    set name "LAN_to_Internet_Outbound"
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "HTTP" "HTTPS" "DNS"
    # Note: FortiOS 7.2 / 7.4 / 7.6 activates UTM automatically when profiles are applied:
    set ssl-ssh-profile "certificate-inspection"
    set av-profile "default"
    set webfilter-profile "default"
    set nat enable
    set logtraffic all
    set logtraffic-start enable
    set comments "Standard internet access with security inspection"
  next
end`,
    tip: "Always set logtraffic all so that you can view connection history under FortiView / Log & Report."
  },
  {
    id: "tmpl-policy-internal",
    title: "Firewall Policy: Internal LAN to Server (No-NAT / Cross-VLAN)",
    category: "policy-templates",
    tags: ["policy", "template", "internal", "no-nat", "dmz", "server"],
    presets: ["preset-policy-templates"],
    whenToUse: "Inter-VLAN or internal routing policy where private client IP must be preserved without translation.",
    template: `config firewall policy
  edit 0
    set name "LAN_to_Server_NoNAT"
    set srcintf "{{interface}}"
    set dstintf "port2"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "H_{{server_ip}}"
    set action accept
    set schedule "always"
    set service "SVC_Custom_{{port}}" "PING"
    set nat disable
    set logtraffic all
    set comments "Direct server access without NAT"
  next
end`,
    tip: "Keep NAT disabled on internal-to-internal policies so server access logs see the real client IP."
  },
  {
    id: "tmpl-ippool-snat",
    title: "IP Pool: Dedicated Outbound Public NAT Pool",
    category: "policy-templates",
    tags: ["ippool", "nat", "snat", "overload", "public ip"],
    presets: ["preset-policy-templates"],
    whenToUse: "When outgoing traffic must appear from a dedicated public IP address instead of the FortiGate WAN interface IP.",
    template: `# 1. Create the IP Pool
config firewall ippool
  edit "POOL_Public_NAT"
    set type overload
    set startip {{peer_ip}}
    set endip {{peer_ip}}
    set comments "Dedicated public IP pool for NAT"
  next
end

# 2. Attach IP Pool to Outbound Policy
config firewall policy
  edit 0
    set name "LAN_Outbound_Using_Pool"
    set srcintf "{{interface}}"
    set dstintf "wan1"
    set srcaddr "H_{{client_ip}}"
    set dstaddr "all"
    set action accept
    set schedule "always"
    set service "ALL"
    set nat enable
    set ippool enable
    set poolname "POOL_Public_NAT"
    set logtraffic all
  next
end`,
    tip: "Essential for clients connecting to third-party APIs that require whitelist of a specific static public IP."
  },
  {
    id: "tmpl-addr-host",
    title: "Address Object: Single Host IP (/32)",
    category: "object-templates",
    tags: ["address", "object", "host", "ip", "create object"],
    presets: ["preset-object-templates"],
    whenToUse: "Create single host address objects for use in firewall policies, VIPs, or static routing.",
    template: `config firewall address
  edit "H_{{client_ip}}"
    set subnet {{client_ip}} 255.255.255.255
    set comment "Client workstation {{client_ip}}"
  next
  edit "H_{{server_ip}}"
    set subnet {{server_ip}} 255.255.255.255
    set comment "Server {{server_ip}}"
  next
end`,
    tip: "Naming convention tip: Prefix with 'H_' for single host /32 addresses."
  },
  {
    id: "tmpl-addr-subnet",
    title: "Address Object: Subnet Network (/24 or Custom Mask)",
    category: "object-templates",
    tags: ["address", "subnet", "network", "cidr", "create object"],
    presets: ["preset-object-templates"],
    whenToUse: "Define an entire subnet network for routing, firewall rules, or VPN selectors.",
    template: `config firewall address
  edit "NET_Branch_LAN"
    set subnet 192.168.1.0 255.255.255.0
    set comment "Local office branch subnet"
  next
  edit "NET_DataCenter_DMZ"
    set subnet 10.20.30.0 255.255.255.0
    set comment "Data center DMZ subnet"
  next
end`,
    tip: "Naming convention tip: Prefix with 'NET_' for subnets."
  },
  {
    id: "tmpl-addr-fqdn",
    title: "Address Object: FQDN (Fully Qualified Domain Name)",
    category: "object-templates",
    tags: ["address", "fqdn", "domain", "dns", "create object"],
    presets: ["preset-object-templates"],
    whenToUse: "When firewall rules must allow or block dynamic cloud services (e.g. AWS, Microsoft 365, GitHub) by domain name.",
    template: `config firewall address
  edit "FQDN_Cloud_API"
    set type fqdn
    set fqdn "api.github.com"
    set comment "Dynamic GitHub API domain"
  next
  edit "FQDN_Microsoft_Update"
    set type fqdn
    set fqdn "windowsupdate.microsoft.com"
  next
end`,
    tip: "FortiGate periodically resolves FQDN objects in the background; verify DNS servers are configured under 'config system dns'."
  },
  {
    id: "tmpl-addr-range",
    title: "Address Object: IP Range (DHCP / Printer Pool)",
    category: "object-templates",
    tags: ["address", "range", "ip range", "pool", "create object"],
    presets: ["preset-object-templates"],
    whenToUse: "Target a non-CIDR range of contiguous IP addresses.",
    template: `config firewall address
  edit "RNG_Static_Printers"
    set type iprange
    set start-ip 192.168.1.50
    set end-ip 192.168.1.80
    set comment "Office static printer and scanner block"
  next
end`,
    tip: "Useful for grouping non-subnet ranges without needing multiple /32 host entries."
  },
  {
    id: "tmpl-addr-group",
    title: "Address Group (addrgrp): Create & Group Multiple Members",
    category: "object-templates",
    tags: ["group", "addrgrp", "address group", "combine", "members"],
    presets: ["preset-object-templates"],
    whenToUse: "Group multiple hosts, subnets, and FQDNs into a single object for simplified firewall policies.",
    template: `config firewall addrgrp
  edit "GRP_Office_Workstations"
    set member "H_{{client_ip}}" "RNG_Static_Printers"
    set comment "Authorized office endpoints"
  next
  edit "GRP_Critical_Servers"
    set member "H_{{server_ip}}" "NET_DataCenter_DMZ"
    set comment "Production servers"
  next
end`,
    tip: "Policies referencing address groups automatically apply to any new member added to the group later."
  },
  {
    id: "tmpl-svc-custom",
    title: "Service Object: Custom TCP / UDP Port Object",
    category: "object-templates",
    tags: ["service", "port", "custom service", "tcp", "udp", "create object"],
    presets: ["preset-object-templates"],
    whenToUse: "When your application uses non-standard ports not included in the FortiGate default service catalog.",
    template: `config firewall service custom
  edit "SVC_Custom_{{port}}"
    set tcp-portrange {{port}}
    set comment "Custom application port {{port}}"
  next
  edit "SVC_High_App_Range"
    set tcp-portrange 8080-8090
    set udp-portrange 8080-8090
    set comment "High range web and media ports"
  next
end`,
    tip: "For multiple disjoint ports, separate with colons or ranges (e.g. '8000:8080:9000-9010')."
  },
  {
    id: "tmpl-svc-group",
    title: "Service Group (service group): Combine Multiple Services",
    category: "object-templates",
    tags: ["service group", "combine services", "ports group"],
    presets: ["preset-object-templates"],
    whenToUse: "Group web, DNS, and custom application ports together for cleaner firewall rules.",
    template: `config firewall service group
  edit "GRP_Corporate_App_Ports"
    set member "HTTP" "HTTPS" "SVC_Custom_{{port}}" "DNS"
    set comment "Standard office application ports"
  next
end`,
    tip: "Simplifies policy rules so you only need a single service entry in the firewall policy."
  },
  {
    id: "tmpl-vip-dnat",
    title: "Virtual IP (VIP / Port Forwarding DNAT) + Inbound Policy",
    category: "vip-templates",
    tags: ["vip", "port forwarding", "dnat", "virtual ip", "inbound policy", "publish server"],
    presets: ["preset-vip-templates"],
    whenToUse: "Publish an internal private server to the internet or WAN using port forwarding.",
    template: `# Step 1: Create the Virtual IP (DNAT Translation)
config firewall vip
  edit "VIP_Public_App_{{port}}"
    set extip {{peer_ip}}
    set mappedip "{{server_ip}}"
    set extintf "wan1"
    set portforward enable
    set protocol tcp
    set extport {{port}}
    set mappedport {{port}}
    set comment "Port forward public {{peer_ip}}:{{port}} to {{server_ip}}:{{port}}"
  next
end

# Step 2: Create Inbound Firewall Policy for the VIP
config firewall policy
  edit 0
    set name "Inbound_WAN_to_VIP_{{port}}"
    set srcintf "wan1"
    set dstintf "{{interface}}"
    set srcaddr "all"
    set dstaddr "VIP_Public_App_{{port}}"
    set action accept
    set schedule "always"
    set service "SVC_Custom_{{port}}"
    # Note: FortiOS 7.2 / 7.4 / 7.6 activates UTM automatically via ips-sensor:
    set ips-sensor "default"
    set nat disable                    # MUST be disable for VIP!
    set logtraffic all
  next
end`,
    tip: "CRITICAL: In the firewall policy, 'dstaddr' MUST be the name of the VIP object ('VIP_Public_App_{{port}}'), and 'nat' MUST be set to disable."
  },
  {
    id: "tmpl-route-static",
    title: "Static Route: Destination Subnet & Default WAN Gateway",
    category: "route-templates",
    tags: ["routing", "static route", "default gateway", "fib", "nexthop"],
    presets: ["preset-policy-templates"],
    whenToUse: "Add static route to internal subnets, remote VPN endpoints, or configure default internet gateway.",
    template: `# Specific destination route to internal server/subnet:
config router static
  edit 0
    set dst {{server_ip}} 255.255.255.255
    set gateway {{fortigate_ip}}
    set device "{{interface}}"
    set comment "Direct static route to {{server_ip}}"
  next
end

# Default Gateway (0.0.0.0/0) Route out to ISP:
config router static
  edit 0
    set dst 0.0.0.0 0.0.0.0
    set gateway {{peer_ip}}
    set device "wan1"
    set distance 10
    set comment "Primary internet default gateway"
  next
end`,
    tip: "Distance determines route priority in RIB. Lowest distance wins (default distance is 10 for static routes)."
  },
  {
    id: "tmpl-route-pbr",
    title: "Policy-Based Route (PBR / Source-Based Routing)",
    category: "route-templates",
    tags: ["pbr", "policy route", "source routing", "sd-wan bypass"],
    presets: ["preset-policy-templates"],
    whenToUse: "Force a specific host or subnet out a specific WAN gateway, bypassing the standard destination routing table.",
    template: `# Force traffic from {{client_ip}} out secondary WAN
config router policy
  edit 0
    set input-device "{{interface}}"
    set src {{client_ip}} 255.255.255.255
    set dst 0.0.0.0 0.0.0.0
    set gateway {{peer_ip}}
    set output-device "wan1"
    set comments "Policy-based route for {{client_ip}}"
  next
end`,
    tip: "Policy routes are evaluated BEFORE standard routing table (FIB). Verify precedence using 'diagnose debug flow'."
  },
  {
    id: "tmpl-vlan-subintf",
    title: "VLAN Sub-Interface & DHCP Server Creation",
    category: "route-templates",
    tags: ["vlan", "subinterface", "802.1q", "dhcp", "interface create"],
    presets: ["preset-object-templates"],
    whenToUse: "Create a tagged 802.1Q VLAN interface on a physical port and configure an automated DHCP server for clients.",
    template: `# 1. Create the VLAN sub-interface
config system interface
  edit "VLAN_Corporate_10"
    set vdom "root"
    set ip 192.168.10.1 255.255.255.0
    set allowaccess ping https ssh
    set interface "{{interface}}"
    set vlanid 10
    set role lan
  next
end

# 2. Configure DHCP Server on the new VLAN
config system dhcp server
  edit 0
    set default-gateway 192.168.10.1
    set netmask 255.255.255.0
    set interface "VLAN_Corporate_10"
    config ip-range
      edit 1
        set start-ip 192.168.10.100
        set end-ip 192.168.10.200
      next
    end
    set dns-service default
  next
end`,
    tip: "Ensure upstream switch port is configured as an 802.1Q trunk allowing VLAN ID 10."
  },

  // =========================================================================
  // SECTION 3: CORE DIAGNOSTICS & PACKET TRACING
  // =========================================================================
  {
    id: "debug-flow-full",
    title: "Debug Flow: Full Drop, Policy & NAT Trace",
    category: "flow",
    tags: ["drop", "deny", "policy", "nat", "rpf", "flow", "trace", "allow", "implicit deny", "asymmetric"],
    presets: ["preset-packet-drop", "preset-asymmetric"],
    whenToUse: "Run when packets reach the FortiGate but connection fails. Shows which firewall policy ID matched, whether it hit implicit deny (policy 0), NAT translations, or asymmetric routing (RPF drop).",
    template: `# 1. Reset existing debug filters
diagnose debug reset

# 2. Filter traffic by source and destination
diagnose debug flow filter saddr {{client_ip}}
diagnose debug flow filter daddr {{server_ip}}
diagnose debug flow filter proto 6              # 6=TCP, 1=ICMP, 17=UDP
diagnose debug flow filter port {{port}}

# 3. Enable flow display & trace counter
diagnose debug flow show function-name enable
diagnose debug flow trace start 100
diagnose debug console timestamp enable
diagnose debug enable

# 4. >>> TRIGGER TRAFFIC FROM CLIENT ({{client_ip}}) NOW <<<

# 5. Stop debug immediately after test
diagnose debug disable
diagnose debug flow trace stop
diagnose debug reset`,
    tip: "Look for 'Allowed by Policy-X' or 'Denied by policy 0'. If you see 'Reverse path check failed, drop', check routing asymmetry."
  },
  {
    id: "debug-flow-icmp",
    title: "Debug Flow: Ping (ICMP) Drop Trace",
    category: "flow",
    tags: ["ping", "icmp", "drop", "flow", "trace"],
    presets: ["preset-packet-drop"],
    whenToUse: "Run when internal host cannot ping an external server or cross-VLAN gateway to verify if FortiOS drops the ICMP echo.",
    template: `diagnose debug reset
diagnose debug flow filter saddr {{client_ip}}
diagnose debug flow filter daddr {{server_ip}}
diagnose debug flow filter proto 1              # 1 = ICMP
diagnose debug flow show function-name enable
diagnose debug flow trace start 50
diagnose debug console timestamp enable
diagnose debug enable

# Trigger ping from {{client_ip}} to {{server_ip}}

diagnose debug disable
diagnose debug flow trace stop
diagnose debug reset`,
    tip: "If you see 'Find a route: gw-...' and outgoing packet leaves, but no return packet arrives, check the destination host's local firewall."
  },
  {
    id: "sniffer-client-server",
    title: "Packet Sniffer: Client to Server on Port",
    category: "sniffer",
    tags: ["sniffer", "packet", "pcap", "tcpdump", "wireshark", "interface"],
    presets: ["preset-packet-drop"],
    whenToUse: "Run to verify if packets physically arrive at the FortiGate port, which interface they enter, and if server replies are received.",
    template: `diagnose sniffer packet {{interface}} 'host {{client_ip}} and host {{server_ip}} and port {{port}}' 4 0 l`,
    tip: "Verbose 4 prints interface name + IP header + port. Press Ctrl + C to stop capturing."
  },
  {
    id: "sniffer-icmp",
    title: "Packet Sniffer: ICMP (Ping) on All Interfaces",
    category: "sniffer",
    tags: ["sniffer", "icmp", "ping", "test"],
    presets: ["preset-packet-drop"],
    whenToUse: "Run to verify bi-directional ping packets (Echo Request and Echo Reply) across all ports on the firewall.",
    template: `diagnose sniffer packet any 'icmp and host {{client_ip}}' 4 40 l`,
    tip: "If you only see incoming packets on LAN and no outgoing packets on WAN, check your Firewall Policy and NAT configuration."
  },
  {
    id: "sniffer-full-pcap",
    title: "Packet Sniffer: Full Hex Payload (Wireshark Importable)",
    category: "sniffer",
    tags: ["sniffer", "hex", "wireshark", "payload", "pcap"],
    presets: [],
    whenToUse: "Run when deep packet analysis is needed. The hex dump can be converted to .pcap using text2pcap or fgt2eth.pl.",
    template: `diagnose sniffer packet {{interface}} 'host {{client_ip}} and port {{port}}' 6 100 l`,
    tip: "Verbose 6 logs Ethernet header + IP header + complete payload hex dump with timestamps."
  },
  {
    id: "session-filter-list",
    title: "Session Table: Inspect Active Connection State",
    category: "session",
    tags: ["session", "state", "established", "syn_sent", "stuck"],
    presets: ["preset-stuck-session"],
    whenToUse: "Run to verify if a TCP connection is established (SYN/ACK complete) or stuck in SYN_SENT / CLOSE_WAIT state.",
    template: `diagnose sys session filter clear
diagnose sys session filter src {{client_ip}}
diagnose sys session filter dst {{server_ip}}
diagnose sys session filter dport {{port}}
diagnose sys session list`,
    tip: "proto_state=01 means established TCP handshake. If proto_state=00 or syn_sent, the remote target is not responding."
  },
  {
    id: "session-clear-rule",
    title: "Session Table: Flush Stuck Sessions (Post-Rule Change)",
    category: "session",
    tags: ["session", "clear", "flush", "reset", "stuck"],
    presets: ["preset-stuck-session"],
    whenToUse: "Run immediately after changing a firewall policy or NAT rule to terminate persistent sessions still running under the old policy.",
    template: `diagnose sys session filter clear
diagnose sys session filter src {{client_ip}}
diagnose sys session filter dst {{server_ip}}
diagnose sys session filter dport {{port}}
diagnose sys session clear
diagnose sys session filter clear`,
    tip: "ALWAYS run 'diagnose sys session filter clear' afterwards to prevent subsequent commands from filtering."
  },
  {
    id: "ping-source-interface",
    title: "Execute Ping: Bind to Source LAN / Interface IP",
    category: "ping",
    tags: ["ping", "source", "interface", "lan", "vpn"],
    presets: ["preset-vpn-down"],
    whenToUse: "Run when testing reachability across an IPsec tunnel or private MPLS where remote routers block ping from the FortiGate's WAN IP.",
    template: `execute ping-options source {{fortigate_ip}}
execute ping-options view-settings
execute ping {{server_ip}}
execute ping-options reset`,
    tip: "Always execute ping-options reset when finished so future CLI pings use normal routing."
  },
  {
    id: "traceroute-source",
    title: "Execute Traceroute: Bind to Source IP",
    category: "ping",
    tags: ["traceroute", "hop", "latency", "source"],
    presets: [],
    whenToUse: "Run to pinpoint which intermediate hop or upstream provider drops packets when traversing complex WANs.",
    template: `execute traceroute-options source {{fortigate_ip}}
execute traceroute {{server_ip}}`,
    tip: "Three consecutive asterisks (***) indicate a non-responding hop, firewall drop, or ISP boundary."
  },
  {
    id: "route-lookup-specific",
    title: "Routing Table: Detailed FIB Route Lookup for Destination",
    category: "routing",
    tags: ["route", "fib", "gateway", "nexthop", "interface"],
    presets: ["preset-asymmetric"],
    whenToUse: "Run to confirm the exact next-hop gateway and egress interface FortiOS will select for a destination IP.",
    template: `get router info routing-table details {{server_ip}}`,
    tip: "Displays distance, metric, next-hop gateway, and egress port. If no specific route matches, it defaults to 0.0.0.0/0."
  },
  {
    id: "route-bgp-summary",
    title: "BGP: Neighbor State and Prefix Summary",
    category: "routing",
    tags: ["bgp", "neighbor", "prefix", "isp", "routing"],
    presets: [],
    whenToUse: "Run when BGP peering with an ISP or cloud gateway (Azure/AWS) is down or routes are missing.",
    template: `get router info bgp summary
get router info bgp neighbors {{bgp_ip}} routes
get router info bgp neighbors {{bgp_ip}} advertised-routes`,
    tip: "Under State/PfxRcd, you should see the number of received prefixes. If it says 'Active' or 'Idle', peering is not established."
  },
  {
    id: "route-bgp-soft-clear",
    title: "BGP: Non-Disruptive Soft Reset (Inbound)",
    category: "routing",
    tags: ["bgp", "soft", "clear", "refresh"],
    presets: [],
    whenToUse: "Run to refresh BGP route advertisements after changing inbound route-maps or prefix-lists without dropping the BGP session.",
    template: `execute router clear bgp {{bgp_ip}} soft in`,
    tip: "Sends a BGP Route Refresh message without dropping TCP port 179."
  },
  {
    id: "vpn-ipsec-status",
    title: "IPsec VPN: Tunnel Summary & Phase 1/2 Check",
    category: "ipsec",
    tags: ["vpn", "ipsec", "phase1", "phase2", "tunnel", "status"],
    presets: ["preset-vpn-down"],
    whenToUse: "Run to immediately verify if Phase 1 (IKE) and Phase 2 (IPsec SA) are UP, and inspect RX/TX byte counters.",
    template: `get vpn ipsec tunnel summary
diagnose vpn tunnel list name {{tunnel_name}}
diagnose vpn ike gateway list name {{tunnel_name}}`,
    tip: "Look for 'proxyid' lines. If rx=0 and tx>0, packets are being sent but the remote peer is not transmitting back."
  },
  {
    id: "vpn-ipsec-debug",
    title: "IPsec VPN: Live IKE Negotiation Debug Trace",
    category: "ipsec",
    tags: ["vpn", "ipsec", "ike", "debug", "phase1", "phase2", "proposal", "psk"],
    presets: ["preset-vpn-down"],
    whenToUse: "Run when a site-to-site VPN will not establish. Exposes PSK mismatches, encryption proposal mismatches, or selector errors.",
    template: `diagnose debug reset
diagnose vpn ike log-filter clear
diagnose vpn ike log-filter dst-addr4 {{peer_ip}}
diagnose debug app ike -1
diagnose debug console timestamp enable
diagnose debug enable

# Force renegotiation:
diagnose vpn ike restart {{tunnel_name}}

# Turn off debug immediately
diagnose debug disable
diagnose debug reset`,
    tip: "'no proposal chosen' = cipher/DH mismatch. 'pre-shared key mismatch' = bad PSK. 'INVALID_ID_INFORMATION' = Phase 2 selector mismatch."
  },
  {
    id: "sslvpn-active-users",
    title: "SSL VPN: Monitor Active Users & Drop Stuck Session",
    category: "sslvpn",
    tags: ["ssl", "vpn", "user", "disconnect", "remote"],
    presets: ["preset-ssl-vpn"],
    whenToUse: "Run to view connected remote workers, their assigned tunnel IP, and disconnect a frozen user.",
    template: `# View all connected SSL VPN users
get vpn ssl monitor

# Force disconnect a specific user
execute vpn ssl-vpn drop-user {{username}}`,
    tip: "Displays real public IP, assigned virtual IP, tunnel duration, and byte volume."
  },
  {
    id: "sslvpn-auth-debug",
    title: "SSL VPN: Authentication & Daemon Debug (LDAP/RADIUS/SAML)",
    category: "sslvpn",
    tags: ["ssl", "vpn", "auth", "ldap", "radius", "saml", "login"],
    presets: ["preset-ssl-vpn"],
    whenToUse: "Run when users receive 'Credential or SSL VPN configuration is wrong (-8)' in FortiClient.",
    template: `diagnose debug reset
diagnose debug app sslvpn -1
diagnose debug app fnbamd -1         # Fortinet Authentication Daemon
diagnose debug console timestamp enable
diagnose debug enable

# Have {{username}} attempt login now

diagnose debug disable
diagnose debug reset`,
    tip: "fnbamd will output LDAP bind errors, bad credentials, group membership mismatches, or SAML assertion rejections."
  },
  {
    id: "system-perf-top",
    title: "System: CPU, Memory & Live Process Monitor (Top)",
    category: "system",
    tags: ["cpu", "memory", "top", "kill", "process", "load", "crash"],
    presets: ["preset-high-cpu"],
    whenToUse: "Run when FortiGate is sluggish, entering conserve mode, or experiencing high CPU load.",
    template: `# System performance overview
get system performance status

# Live process monitor (press 'q' to quit, 'm' to sort memory, 'p' to sort CPU)
diagnose sys top 2 20`,
    tip: "Common daemons: 'wad' (web proxy/SSL inspection), 'ipsengine' (IPS), 'miglogd' (logging). Restart wad with: diagnose test application wad 99"
  },
  {
    id: "system-crash-log",
    title: "System: Crash Log & Daemon Core Dump Inspection",
    category: "system",
    tags: ["crash", "daemon", "segfault", "log", "reboot"],
    presets: ["preset-high-cpu"],
    whenToUse: "Run after unexpected reboots or service failures to see which security daemon crashed.",
    template: `diagnose debug crashlog read`,
    tip: "Repeated crash log entries for the same daemon indicate a bug that likely requires a firmware patch."
  },
  {
    id: "network-arp-clear",
    title: "ARP: View Bindings & Flush Interface Cache",
    category: "network",
    tags: ["arp", "mac", "interface", "flush", "cache"],
    presets: ["preset-arp-mac"],
    whenToUse: "Run after replacing a router, firewall, or server NIC to force FortiGate to immediately learn the new MAC address.",
    template: `# View current ARP cache
get system arp

# Flush ARP cache on specific interface
execute clear system arp interface {{interface}}`,
    tip: "Prevents having to wait for the default 5-minute ARP expiration timer."
  },
  {
    id: "network-nic-stats",
    title: "Interface: Hardware NIC Counters & SFP Optics (DDM)",
    category: "network",
    tags: ["nic", "duplex", "drops", "errors", "sfp", "optics", "speed"],
    presets: [],
    whenToUse: "Run when you suspect a damaged cable, duplex mismatch, CRC errors, or low optical transceiver power.",
    template: `get system interface physical
diagnose hardware deviceinfo nic {{interface}}`,
    tip: "Look for 'Rx CRC errors', 'Rx dropped', and SFP optical levels (Tx Power / Rx Power in dBm)."
  },
  {
    id: "ha-checksum-sync",
    title: "HA: Verify Cluster Sync & Manage Secondary Node",
    category: "ha",
    tags: ["ha", "cluster", "sync", "checksum", "failover", "primary", "secondary"],
    presets: [],
    whenToUse: "Run to verify active/passive cluster is synchronized and manage the standby unit CLI without moving console cables.",
    template: `# Check cluster status and roles
get system ha status

# Compare checksums (ALL NODES MUST MATCH)
diagnose sys ha checksum cluster

# SSH into Secondary node CLI (index 2)
execute ha manage 2`,
    tip: "If checksums do not match, run 'diagnose sys ha checksum recalculate' on the out-of-sync node."
  },
  {
    id: "backup-tftp",
    title: "Backup & Revisions: Off-Box TFTP Backup & Diffs",
    category: "backup",
    tags: ["backup", "tftp", "config", "revision", "diff"],
    presets: [],
    whenToUse: "Run before major configuration changes or firmware upgrades to guarantee an offline recovery point.",
    template: `# Backup config to TFTP server
execute backup config tftp FG_{{hostname}}_backup.conf {{tftp_ip}}

# Check on-box revision history
execute revision list`,
    tip: "Run 'execute revision diff <id1> <id2>' to compare exact line-by-line differences between two configurations."
  }
];

// Variable Registry & Defaults
const defaultVars = {
  hostname: "FGT-OFFICE-FW01",
  client_ip: "192.168.1.100",
  server_ip: "10.20.30.50",
  port: "443",
  interface: "any",
  fortigate_ip: "192.168.1.1",
  peer_ip: "203.0.113.50",
  tunnel_name: "VPN_Branch_Site",
  bgp_ip: "198.51.100.1",
  username: "john.smith",
  tftp_ip: "192.168.1.200"
};

let currentVars = { ...defaultVars };
let currentSection = "policy";
let currentCategory = "all";
let searchQuery = "";

// 5 Master Sections Configuration
const SECTIONS = {
  policy: {
    id: "policy",
    title: "Policies & Objects",
    icon: "📜",
    summary: "Firewall rules, address objects, groups, VIP port forwards, and CLI policy ordering",
    categories: [
      { id: "all", label: "All Policies & Objects", icon: "📁" },
      { id: "workflow", label: "Step-by-Step Policy Builder", icon: "📋" },
      { id: "policy-templates", label: "Firewall Policy Templates", icon: "📜" },
      { id: "object-templates", label: "Addresses, Groups & FQDNs", icon: "📦" },
      { id: "vip-templates", label: "VIP & Port Forwarding", icon: "🔀" },
      { id: "cli-ops", label: "CLI Policy Reorder & Hit Counters", icon: "⌨️" }
    ]
  },
  sdwan: {
    id: "sdwan",
    title: "SD-WAN & Routing",
    icon: "🌐",
    summary: "SD-WAN zones, member interfaces, SLA health-checks, steering rules, PBR & static routes",
    categories: [
      { id: "all", label: "All SD-WAN & Routing", icon: "📁" },
      { id: "sdwan", label: "SD-WAN Zones & SLA Steering", icon: "🌐" },
      { id: "pbr", label: "Policy-Based Routing (PBR)", icon: "🧭" },
      { id: "route-templates", label: "Static Routes (sdwan-zone) & BGP", icon: "🛣️" },
      { id: "routing", label: "Routing Table & FIB Verification", icon: "🧭" },
      { id: "workflow-route", label: "Static Route Step-by-Step", icon: "📋" }
    ]
  },
  interfaces: {
    id: "interfaces",
    title: "Interfaces & Migration",
    icon: "🔌",
    summary: "Physical ports, 802.1Q VLAN subinterfaces, 802.3ad LACP trunks & zero-loss reference migration",
    categories: [
      { id: "all", label: "All Interfaces & Migration", icon: "📁" },
      { id: "interfaces", label: "Physical, VLAN & LACP Trunks", icon: "🔌" },
      { id: "migration", label: "Zero-Loss Reference Migration", icon: "🔄" },
      { id: "network", label: "ARP, MAC Table & Port Diag", icon: "🔍" },
      { id: "workflow-vlan", label: "VLAN & DHCP Step-by-Step", icon: "📋" }
    ]
  },
  vpn: {
    id: "vpn",
    title: "VPNs (IPsec & SSL)",
    icon: "🔐",
    summary: "Route-based IKEv2 site-to-site IPsec tunnels, dial-up VPNs & SSL-VPN portals",
    categories: [
      { id: "all", label: "All VPN Configurations", icon: "📁" },
      { id: "ipsec", label: "Route-Based IPsec (IKEv2)", icon: "🔐" },
      { id: "sslvpn", label: "SSL-VPN Portals & Tunnels", icon: "👥" },
      { id: "workflow-ipsec", label: "IPsec Step-by-Step Builder", icon: "📋" }
    ]
  },
  troubleshoot: {
    id: "troubleshoot",
    title: "Troubleshooting & Diagnostics",
    icon: "🚨",
    summary: "Debug flow, Wireshark-level packet sniffers, session clearing, crash logs, error resolver & parse shield",
    categories: [
      { id: "all", label: "All Diagnostics", icon: "📁" },
      { id: "flow", label: "Debug Flow (Packet Tracer)", icon: "🔬" },
      { id: "sniffer", label: "Packet Sniffer (Raw Frames)", icon: "📡" },
      { id: "session", label: "Session Table & Clear Stuck", icon: "📑" },
      { id: "error-logs", label: "Error Log Resolver (Smoking Gun)", icon: "🚨" },
      { id: "syntax-shield", label: "Syntax Shield (Parse Errors)", icon: "🛡️" },
      { id: "system", label: "High CPU, Conserve Mode & Crashes", icon: "🔥" },
      { id: "ping", label: "Ping & Traceroute Options", icon: "📍" },
      { id: "ha", label: "HA Cluster & Sync Verification", icon: "👥" },
      { id: "backup", label: "Backup & Revision Management", icon: "💾" },
      { id: "reference-decoder", label: "📋 Reference Log & Syntax Tables", icon: "📖" }
    ]
  }
};

const CATEGORY_TO_SECTION = {
  "workflow": "policy",
  "policy-templates": "policy",
  "object-templates": "policy",
  "vip-templates": "policy",
  "cli-ops": "policy",

  "sdwan": "sdwan",
  "pbr": "sdwan",
  "route-templates": "sdwan",
  "routing": "sdwan",

  "interfaces": "interfaces",
  "migration": "interfaces",
  "network": "interfaces",

  "ipsec": "vpn",
  "sslvpn": "vpn",

  "flow": "troubleshoot",
  "sniffer": "troubleshoot",
  "session": "troubleshoot",
  "ping": "troubleshoot",
  "system": "troubleshoot",
  "ha": "troubleshoot",
  "backup": "troubleshoot",
  "error-logs": "troubleshoot",
  "syntax-shield": "troubleshoot"
};

const COMMAND_SECTION_OVERRIDES = {
  "workflow-route-creation": "sdwan",
  "workflow-vlan-creation": "interfaces",
  "workflow-ipsec-creation": "vpn"
};

function getCommandSection(cmd) {
  if (COMMAND_SECTION_OVERRIDES[cmd.id]) return COMMAND_SECTION_OVERRIDES[cmd.id];
  return CATEGORY_TO_SECTION[cmd.category] || "troubleshoot";
}

// Load from LocalStorage
function loadStoredVars() {
  try {
    const saved = localStorage.getItem("fgt_portal_vars");
    if (saved) {
      const parsed = JSON.parse(saved);
      currentVars = { ...defaultVars, ...parsed };
    }
    const savedSection = localStorage.getItem("fgt_portal_section");
    if (savedSection && SECTIONS[savedSection]) {
      currentSection = savedSection;
    }
  } catch (e) {
    console.error("Local storage load failed", e);
  }
}

// Save to LocalStorage
function saveStoredVars() {
  try {
    localStorage.setItem("fgt_portal_vars", JSON.stringify(currentVars));
  } catch (e) {
    console.error("Local storage save failed", e);
  }
}

// Sync UI inputs with variables
function syncInputFields() {
  const map = {
    "var-hostname": "hostname",
    "var-client-ip": "client_ip",
    "var-server-ip": "server_ip",
    "var-port": "port",
    "var-interface": "interface",
    "var-fortigate-ip": "fortigate_ip",
    "var-peer-ip": "peer_ip",
    "var-tunnel-name": "tunnel_name",
    "var-bgp-ip": "bgp_ip",
    "var-username": "username",
    "var-tftp-ip": "tftp_ip"
  };

  Object.entries(map).forEach(([inputId, varKey]) => {
    const el = document.getElementById(inputId);
    if (el) {
      el.value = currentVars[varKey] || "";
      el.addEventListener("input", (e) => {
        currentVars[varKey] = e.target.value.trim() || defaultVars[varKey];
        saveStoredVars();
        updateHostnameDisplays();
        renderCards();
      });
    }
  });

  updateHostnameDisplays();
}

function updateHostnameDisplays() {
  const host = currentVars.hostname || "FGT-OFFICE-FW01";
  const displayBadge = document.getElementById("display-hostname");
  if (displayBadge) displayBadge.textContent = host;

  const cliTitle = document.getElementById("cli-console-title");
  if (cliTitle) cliTitle.textContent = `FortiGate CLI Console - ${host} (root)`;

  const cliPrompt = document.getElementById("cli-active-prompt");
  if (cliPrompt) cliPrompt.textContent = `${host} # `;
}

// Interpolate with HTML highlight spans
function interpolateWithHighlight(template, vars) {
  if (!template) return "";
  let text = escapeHtml(template);
  Object.entries(vars).forEach(([key, val]) => {
    const regex = new RegExp(`\\{\\{${key}\\}\\}`, "g");
    text = text.replace(regex, `<span class="val-highlight">${escapeHtml(val)}</span>`);
  });

  const lines = text.split("\n").map(line => {
    if (line.trim().startsWith("#")) {
      return `<span class="comment-line">${line}</span>`;
    }
    return line;
  });

  return lines.join("\n");
}

// Plain interpolation for clipboard copy
function interpolatePlain(template, vars) {
  if (!template) return "";
  let text = template;
  Object.entries(vars).forEach(([key, val]) => {
    const regex = new RegExp(`\\{\\{${key}\\}\\}`, "g");
    text = text.replace(regex, val);
  });
  return text;
}

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Filter commands
function getFilteredCommands() {
  return COMMANDS.filter(cmd => {
    const cmdSection = getCommandSection(cmd);

    // If searching globally, allow cross-section matches
    if (!searchQuery) {
      if (cmdSection !== currentSection) return false;
    }

    if (currentCategory !== "all") {
      if (currentCategory === "workflow-route") {
        if (cmd.id !== "workflow-route-creation") return false;
      } else if (currentCategory === "workflow-vlan") {
        if (cmd.id !== "workflow-vlan-creation") return false;
      } else if (currentCategory === "workflow-ipsec") {
        if (cmd.id !== "workflow-ipsec-creation") return false;
      } else if (currentCategory === "reference-decoder") {
        return false;
      } else if (cmd.category !== currentCategory) {
        return false;
      }
    }

    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchTitle = cmd.title.toLowerCase().includes(q);
      const matchWhen = cmd.whenToUse.toLowerCase().includes(q);
      const matchTags = cmd.tags.some(tag => tag.toLowerCase().includes(q));
      const matchCmd = cmd.template.toLowerCase().includes(q);
      const matchNeedle = cmd.criticalNeedle ? cmd.criticalNeedle.toLowerCase().includes(q) : false;
      const matchRaw = cmd.rawLog ? cmd.rawLog.toLowerCase().includes(q) : false;
      if (!matchTitle && !matchWhen && !matchTags && !matchCmd && !matchNeedle && !matchRaw) return false;
    }

    return true;
  });
}

function updateSectionCounts() {
  const counts = { policy: 0, sdwan: 0, interfaces: 0, vpn: 0, troubleshoot: 0 };
  COMMANDS.forEach(cmd => {
    const sec = getCommandSection(cmd);
    if (counts[sec] !== undefined) counts[sec]++;
  });

  Object.entries(counts).forEach(([sec, cnt]) => {
    const el = document.getElementById(`section-count-${sec}`);
    if (el) el.textContent = cnt;
  });
}

function renderSidebar() {
  const sectionConfig = SECTIONS[currentSection] || SECTIONS.policy;
  const headingEl = document.getElementById("sidebar-section-heading");
  if (headingEl) {
    headingEl.textContent = sectionConfig.title;
  }

  const sectionCmds = COMMANDS.filter(cmd => getCommandSection(cmd) === currentSection);

  function getCategoryCount(cat) {
    if (cat.id === "all") return sectionCmds.length;
    if (cat.id === "workflow-route") return sectionCmds.filter(c => c.id === "workflow-route-creation").length;
    if (cat.id === "workflow-vlan") return sectionCmds.filter(c => c.id === "workflow-vlan-creation").length;
    if (cat.id === "workflow-ipsec") return sectionCmds.filter(c => c.id === "workflow-ipsec-creation").length;
    if (cat.id === "reference-decoder") return "Ref";
    return sectionCmds.filter(c => c.category === cat.id).length;
  }

  // 1. Render Desktop Sidebar
  const navEl = document.getElementById("category-nav");
  if (navEl) {
    navEl.innerHTML = sectionConfig.categories.map(cat => {
      const count = getCategoryCount(cat);
      const isActive = (cat.id === currentCategory) ? "active" : "";

      return `
        <button class="nav-item ${isActive}" data-category="${cat.id}">
          <span class="nav-icon">${cat.icon}</span>
          <span class="nav-text">${escapeHtml(cat.label)}</span>
          <span class="nav-count">${count}</span>
        </button>
      `;
    }).join("");

    navEl.querySelectorAll(".nav-item").forEach(item => {
      item.addEventListener("click", () => {
        handleCategorySelect(item.getAttribute("data-category"));
      });
    });
  }

  // 2. Render Mobile Subcategory Chips Bar
  const mobileNavEl = document.getElementById("mobile-category-bar");
  if (mobileNavEl) {
    mobileNavEl.innerHTML = sectionConfig.categories.map(cat => {
      const count = getCategoryCount(cat);
      const isActive = (cat.id === currentCategory) ? "active" : "";

      return `
        <button class="mobile-chip ${isActive}" data-category="${cat.id}">
          <span class="chip-icon">${cat.icon}</span>
          <span class="chip-label">${escapeHtml(cat.label)}</span>
          <span class="chip-count">${count}</span>
        </button>
      `;
    }).join("");

    mobileNavEl.querySelectorAll(".mobile-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        handleCategorySelect(chip.getAttribute("data-category"));
      });
    });
  }
}

function handleCategorySelect(cat) {
  if (cat === "reference-decoder") {
    const decBox = document.getElementById("log-decoder");
    if (decBox) {
      decBox.style.display = "block";
      decBox.scrollIntoView({ behavior: "smooth" });
    }
    return;
  }
  currentCategory = cat;
  renderSidebar();
  renderCards();
}

// Render cards
function renderCards() {
  const container = document.getElementById("cards-container");
  const countText = document.getElementById("results-count-text");
  const filtered = getFilteredCommands();
  const host = currentVars.hostname || "FGT-OFFICE-FW01";

  // Hide or show bottom reference decoder tables
  const decoderBox = document.getElementById("log-decoder");
  if (decoderBox) {
    if (currentSection === "troubleshoot" || currentCategory === "reference-decoder") {
      decoderBox.style.display = "block";
    } else {
      decoderBox.style.display = "none";
    }
  }

  const secTitle = SECTIONS[currentSection]?.title || "FortiOS Operations";
  if (searchQuery) {
    countText.textContent = `Search results: ${filtered.length} operations matching "${searchQuery}"`;
  } else {
    countText.textContent = `Showing ${filtered.length} operations in ${secTitle} • FortiOS v7.2 / v7.4 / v7.6`;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 3rem 1rem; color: var(--text-muted); grid-column: 1 / -1;">
        <p style="font-size: 1.15rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem;">No matching FortiOS operations found</p>
        <p style="font-size: 0.8rem;">Try clearing your search query or selecting "All" from the sidebar navigation.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(cmd => {
    const highlightedCode = interpolateWithHighlight(cmd.template, currentVars);
    const plainCode = interpolatePlain(cmd.template, currentVars);

    // SPECIAL RENDERING FOR ERROR LOG RESOLVER CARDS
    if (cmd.isLogAnalysis) {
      const highlightedDiagCmd = interpolateWithHighlight(cmd.diagCmd, currentVars);
      const plainDiagCmd = interpolatePlain(cmd.diagCmd, currentVars);
      const highlightedRawLog = interpolateWithHighlight(cmd.rawLog, currentVars);

      return `
        <div class="cmd-card log-analysis-card" id="card-${cmd.id}">
          <div class="cmd-card-header">
            <div class="cmd-title-wrap">
              <div class="cmd-meta">
                <span class="category-tag" style="background-color: rgba(239, 68, 68, 0.2); color: #ff8080; border-color: rgba(239, 68, 68, 0.4);">🚨 ERROR LOG RESOLVER</span>
                <span class="fw-badge">FortiOS 7.2 • 7.4 • 7.6</span>
                <span class="zero-db-tag" style="font-size: 0.6rem;">SMOKING GUN FIX</span>
              </div>
              <h3 class="cmd-title">${escapeHtml(cmd.title)}</h3>
            </div>
          </div>

          <div class="cmd-body">
            <div class="scenario-box">
              <strong>SYMPTOM / WHEN TO CHECK:</strong> ${escapeHtml(cmd.whenToUse)}
            </div>

            <!-- STEP 1: CAPTURE COMMAND -->
            <div class="log-section-title">
              <span>🔍 STEP 1: RUN COMMAND TO CAPTURE THIS ERROR LOG</span>
            </div>
            <div class="terminal-block">
              <div class="terminal-header">
                <div class="terminal-left-info"><span class="terminal-prompt-label">${escapeHtml(host)} #</span></div>
                <div class="terminal-actions">
                  <button class="terminal-btn copy-explicit-btn" data-code="${escapeHtml(plainDiagCmd)}" title="Copy capture command">
                    <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/></svg>
                    Copy Capture Cmd
                  </button>
                </div>
              </div>
              <pre class="terminal-code">${highlightedDiagCmd}</pre>
            </div>

            <!-- STEP 2: RAW FORTIOS LOG OUTPUT -->
            <div class="log-section-title">
              <span>📄 STEP 2: SAMPLE RAW FORTIOS DEBUG STREAM</span>
            </div>
            <pre class="raw-log-block">${highlightedRawLog}</pre>

            <!-- STEP 3: CRITICAL SMOKING GUN LOG STRING -->
            <div class="critical-find-box">
              <div class="critical-find-header">
                <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                  <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
                </svg>
                CRITICAL LOG LINE TO SEARCH FOR IN CONSOLE:
              </div>
              <div><span class="critical-needle">${escapeHtml(cmd.criticalNeedle)}</span></div>
              <div style="font-size: 0.74rem; color: #cbd5e1; line-height: 1.45;">${escapeHtml(cmd.criticalExplanation)}</div>
            </div>

            <!-- STEP 4: EXACT CONFIGURATION FIX -->
            <div class="fix-box-header">
              <div class="fix-label">
                <svg viewBox="0 0 20 20" fill="currentColor" width="14" height="14">
                  <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 011 1v1a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                </svg>
                STEP 3: EXACT CLI CONFIGURATION FIX (COPY & APPLY)
              </div>
            </div>
            <div class="terminal-block">
              <div class="terminal-header">
                <div class="terminal-left-info"><span class="terminal-prompt-label">${escapeHtml(host)} (config) #</span></div>
                <div class="terminal-actions">
                  <button class="terminal-btn run-cli-btn" data-cmd-id="${cmd.id}" title="Send fix to Web CLI Console">
                    <span>&gt;_ Run in CLI</span>
                  </button>
                  <button class="terminal-btn copy-btn" data-cmd-id="${cmd.id}" title="Copy CLI Fix">
                    <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/></svg>
                    Copy CLI Fix
                  </button>
                </div>
              </div>
              <pre class="terminal-code" data-code="${escapeHtml(plainCode)}">${highlightedCode}</pre>
            </div>

            ${cmd.tip ? `
              <div class="output-tip">
                <span class="output-tip-icon">💡</span>
                <div>${escapeHtml(cmd.tip)}</div>
              </div>
            ` : ""}
          </div>
        </div>
      `;
    }

    // RENDERING FOR WORKFLOW, SYNTAX-SHIELD, MIGRATION, SDWAN, PBR, TEMPLATE & STANDARD CARDS
    const isTemplate = cmd.category.includes("templates");
    const isWorkflow = cmd.category === "workflow";
    const isSyntax = cmd.category === "syntax-shield";
    const isMigration = cmd.category === "migration";
    const isSdwan = cmd.category === "sdwan";
    const isPbr = cmd.category === "pbr";
    const isInterfaces = cmd.category === "interfaces";

    let cardExtraClass = "";
    if (isTemplate) cardExtraClass = "template-card";
    else if (isWorkflow) cardExtraClass = "workflow-card";
    else if (isSyntax) cardExtraClass = "syntax-card";
    else if (isMigration) cardExtraClass = "migration-card";
    else if (isSdwan) cardExtraClass = "sdwan-card";
    else if (isPbr) cardExtraClass = "pbr-card";
    else if (isInterfaces) cardExtraClass = "interfaces-card";

    let badgeHtml = "";
    if (isTemplate) {
      badgeHtml = `<span class="template-badge">CONFIG TEMPLATE</span>`;
    } else if (isWorkflow) {
      badgeHtml = `<span class="template-badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399; border-color: rgba(16, 185, 129, 0.4);">STEP-BY-STEP WORKFLOW</span>`;
    } else if (isSyntax) {
      badgeHtml = `<span class="template-badge" style="background: rgba(234, 179, 8, 0.2); color: #facc15; border-color: rgba(234, 179, 8, 0.4);">SYNTAX PARSER SHIELD</span>`;
    } else if (isMigration) {
      badgeHtml = `<span class="template-badge" style="background: rgba(139, 92, 246, 0.2); color: #c084fc; border-color: rgba(139, 92, 246, 0.4);">ZERO-LOSS MIGRATION</span>`;
    } else if (isSdwan) {
      badgeHtml = `<span class="template-badge" style="background: rgba(6, 182, 212, 0.2); color: #22d3ee; border-color: rgba(6, 182, 212, 0.4);">SD-WAN ARCHITECTURE</span>`;
    } else if (isPbr) {
      badgeHtml = `<span class="template-badge" style="background: rgba(249, 115, 22, 0.2); color: #fb923c; border-color: rgba(249, 115, 22, 0.4);">POLICY-BASED ROUTE</span>`;
    } else if (isInterfaces) {
      badgeHtml = `<span class="template-badge" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa; border-color: rgba(59, 130, 246, 0.4);">INTERFACE CONFIG</span>`;
    }

    const buttonLabel = isTemplate ? "Copy Template" : isWorkflow ? "Copy Workflow" : isSyntax ? "Copy Syntax Fix" : isMigration ? "Copy Migration Plan" : isSdwan ? "Copy SD-WAN Block" : isPbr ? "Copy PBR Rule" : "Copy Command";

    return `
      <div class="cmd-card ${cardExtraClass}" id="card-${cmd.id}">
        <div class="cmd-card-header">
          <div class="cmd-title-wrap">
            <div class="cmd-meta">
              <span class="category-tag">${cmd.category}</span>
              <span class="fw-badge">FortiOS 7.2 • 7.4 • 7.6</span>
              ${badgeHtml}
            </div>
            <h3 class="cmd-title">${escapeHtml(cmd.title)}</h3>
          </div>
        </div>

        <div class="cmd-body">
          <div class="scenario-box">
            <strong>${isWorkflow ? "WORKFLOW OVERVIEW:" : isSyntax ? "SYNTAX PROBLEM & FIX:" : isTemplate ? "TEMPLATE PURPOSE:" : "WHEN TO USE:"}</strong> ${escapeHtml(cmd.whenToUse)}
          </div>

          <div class="terminal-block">
            <div class="terminal-header">
              <div class="terminal-left-info">
                <span class="terminal-prompt-label">${escapeHtml(host)} #</span>
              </div>
              <div class="terminal-actions">
                <button class="terminal-btn run-cli-btn" data-cmd-id="${cmd.id}" title="Send command to Web CLI Console">
                  <span>&gt;_ Run in CLI</span>
                </button>
                <button class="terminal-btn copy-btn" data-cmd-id="${cmd.id}" title="Copy to clipboard">
                  <svg viewBox="0 0 20 20" fill="currentColor" width="12" height="12">
                    <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
                    <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z" />
                  </svg>
                  ${buttonLabel}
                </button>
              </div>
            </div>
            <pre class="terminal-code" data-code="${escapeHtml(plainCode)}">${highlightedCode}</pre>
          </div>

          ${cmd.tip ? `
            <div class="output-tip">
              <span class="output-tip-icon">💡</span>
              <div>${escapeHtml(cmd.tip)}</div>
            </div>
          ` : ""}
        </div>
      </div>
    `;
  }).join("");

  // Attach event handlers
  document.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const card = btn.closest(".cmd-card");
      const codeEl = card.querySelector(".terminal-code");
      const textToCopy = codeEl.getAttribute("data-code");
      copyToClipboard(textToCopy, btn);
    });
  });

  document.querySelectorAll(".copy-explicit-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const textToCopy = btn.getAttribute("data-code");
      copyToClipboard(textToCopy, btn);
    });
  });

  document.querySelectorAll(".run-cli-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const card = btn.closest(".cmd-card");
      const codeEl = card.querySelector(".terminal-code");
      const text = codeEl.getAttribute("data-code");
      sendToWebCli(text);
    });
  });
}

// Toast
let toastTimeout = null;
function showToast(msg) {
  const toast = document.getElementById("toast");
  const toastMsg = document.getElementById("toast-message");
  if (!toast) return;

  toastMsg.textContent = msg;
  toast.classList.remove("hidden");

  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.classList.add("hidden");
  }, 2200);
}

// Clipboard
function copyToClipboard(text, triggerBtn) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      onCopySuccess(triggerBtn);
    }).catch(() => fallbackCopy(text, triggerBtn));
  } else {
    fallbackCopy(text, triggerBtn);
  }
}

function fallbackCopy(text, triggerBtn) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.left = "-999999px";
  document.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  try {
    document.execCommand("copy");
    onCopySuccess(triggerBtn);
  } catch (err) {
    showToast("Copy failed, please select and copy manually.");
  }
  document.body.removeChild(textarea);
}

function onCopySuccess(triggerBtn) {
  showToast("FortiGate CLI block copied!");
  if (triggerBtn) {
    const originalText = triggerBtn.innerHTML;
    triggerBtn.classList.add("copied");
    triggerBtn.innerHTML = `Copied!`;
    setTimeout(() => {
      triggerBtn.classList.remove("copied");
      triggerBtn.innerHTML = originalText;
    }, 1600);
  }
}

// FortiOS Interactive Web CLI Console Simulation
function sendToWebCli(commandText) {
  const drawer = document.getElementById("cli-console-drawer");
  drawer.classList.remove("hidden");

  const history = document.getElementById("cli-output-history");
  const host = currentVars.hostname || "FGT-OFFICE-FW01";

  const entry = document.createElement("div");
  entry.className = "cli-entry";
  entry.innerHTML = `
    <div class="cli-entry-cmd">${escapeHtml(host)} # <span style="color:#ffffff;">${escapeHtml(commandText)}</span></div>
    <div class="cli-entry-res">[Command loaded for execution on ${escapeHtml(host)}]</div>
  `;
  history.appendChild(entry);

  const body = document.getElementById("cli-terminal-body");
  body.scrollTop = body.scrollHeight;
  showToast("Sent to Web CLI console!");
}

function setupCliConsole() {
  const drawer = document.getElementById("cli-console-drawer");
  const toggleBtn = document.getElementById("toggle-cli-console");
  const closeBtn = document.getElementById("cli-close-btn");
  const clearBtn = document.getElementById("cli-clear-btn");
  const copyAllBtn = document.getElementById("cli-copy-all-btn");
  const stdin = document.getElementById("cli-stdin");
  const history = document.getElementById("cli-output-history");

  toggleBtn.addEventListener("click", () => {
    drawer.classList.toggle("hidden");
    if (!drawer.classList.contains("hidden")) {
      stdin.focus();
    }
  });

  closeBtn.addEventListener("click", () => {
    drawer.classList.add("hidden");
  });

  clearBtn.addEventListener("click", () => {
    history.innerHTML = "";
    stdin.focus();
  });

  copyAllBtn.addEventListener("click", () => {
    const text = history.innerText;
    if (!text.trim()) {
      showToast("CLI console is empty.");
      return;
    }
    copyToClipboard(text, copyAllBtn);
  });

  stdin.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const val = stdin.value.trim();
      if (!val) return;
      const host = currentVars.hostname || "FGT-OFFICE-FW01";

      const entry = document.createElement("div");
      entry.className = "cli-entry";

      let response = "";
      if (val === "clear") {
        history.innerHTML = "";
        stdin.value = "";
        return;
      } else if (val === "get system status") {
        response = `Version: FortiGate-100F v7.4.4,build2573,240417 (GA.M)\nHost: ${host}\nCluster: a-p (Sync OK)\nOS Compatibility: FortiOS v7.2, v7.4, v7.6\nStatus: Normal`;
      } else if (val.startsWith("diagnose")) {
        response = `[FortiOS Diagnostic Hook Initiated for: ${val}]`;
      } else if (val.startsWith("config")) {
        response = `[FortiOS Configuration Mode Entered]`;
      } else {
        response = `Command executed.`;
      }

      entry.innerHTML = `
        <div class="cli-entry-cmd">${escapeHtml(host)} # ${escapeHtml(val)}</div>
        <div class="cli-entry-res">${escapeHtml(response)}</div>
      `;
      history.appendChild(entry);
      stdin.value = "";

      const body = document.getElementById("cli-terminal-body");
      body.scrollTop = body.scrollHeight;
    }
  });
}

// Setup Event Listeners
function setupEvents() {
  // Master Section Tabs
  document.querySelectorAll(".section-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".section-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentSection = tab.getAttribute("data-section");
      currentCategory = "all";
      try {
        localStorage.setItem("fgt_portal_section", currentSection);
      } catch (e) {}
      renderSidebar();
      renderCards();
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  });

  // Toggle Advanced Variables Drawer
  const toggleAdvBtn = document.getElementById("toggle-adv-vars");
  const advDrawer = document.getElementById("advanced-vars-panel");
  if (toggleAdvBtn && advDrawer) {
    toggleAdvBtn.addEventListener("click", () => {
      const isHidden = advDrawer.classList.toggle("hidden");
      toggleAdvBtn.classList.toggle("active", !isHidden);
      toggleAdvBtn.innerHTML = isHidden 
        ? `<svg viewBox="0 0 20 20" fill="currentColor" width="13" height="13"><path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/></svg> More Variables`
        : `<svg viewBox="0 0 20 20" fill="currentColor" width="13" height="13"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg> Close Variables`;
    });
  }

  // Search
  const searchInput = document.getElementById("global-search");
  const clearSearchBtn = document.getElementById("clear-search");

  searchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value.trim();
    clearSearchBtn.classList.toggle("hidden", !searchQuery);
    renderCards();
  });

  clearSearchBtn.addEventListener("click", () => {
    searchInput.value = "";
    searchQuery = "";
    clearSearchBtn.classList.add("hidden");
    searchInput.focus();
    renderCards();
  });

  // Reset Variables
  document.getElementById("reset-variables-btn").addEventListener("click", () => {
    currentVars = { ...defaultVars };
    saveStoredVars();
    syncInputFields();
    renderCards();
    showToast("Variables reset to defaults!");
  });

  // Theme Toggle
  const themeToggle = document.getElementById("theme-toggle");
  const sunIcon = themeToggle.querySelector(".sun-icon");
  const moonIcon = themeToggle.querySelector(".moon-icon");

  themeToggle.addEventListener("click", () => {
    const isLight = document.body.classList.toggle("light-theme");
    document.body.classList.toggle("dark-theme", !isLight);
    sunIcon.classList.toggle("hidden", !isLight);
    moonIcon.classList.toggle("hidden", isLight);
    localStorage.setItem("fgt_portal_theme", isLight ? "light" : "dark");
  });

  if (localStorage.getItem("fgt_portal_theme") === "light") {
    document.body.classList.add("light-theme");
    document.body.classList.remove("dark-theme");
    sunIcon.classList.remove("hidden");
    moonIcon.classList.add("hidden");
  }

  // Copy All Visible Script
  document.getElementById("copy-all-visible").addEventListener("click", () => {
    const visibleCards = document.querySelectorAll(".cmd-card .terminal-code");
    if (visibleCards.length === 0) {
      showToast("No commands currently visible.");
      return;
    }
    const combined = Array.from(visibleCards)
      .map(card => card.getAttribute("data-code"))
      .filter(Boolean)
      .join("\n\n# ----------------------------------------\n\n");
    
    copyToClipboard(combined, document.getElementById("copy-all-visible"));
  });

  // Keyboard shortcut '/'
  window.addEventListener("keydown", (e) => {
    if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
    if (e.key === "Escape" && document.activeElement === searchInput) {
      searchInput.value = "";
      searchQuery = "";
      clearSearchBtn.classList.add("hidden");
      searchInput.blur();
      renderCards();
    }
  });

  setupCliConsole();
}

// Init
document.addEventListener("DOMContentLoaded", () => {
  loadStoredVars();
  syncInputFields();
  updateSectionCounts();

  // Activate stored section tab
  document.querySelectorAll(".section-tab").forEach(tab => {
    tab.classList.toggle("active", tab.getAttribute("data-section") === currentSection);
  });

  renderSidebar();
  setupEvents();
  renderCards();
});

