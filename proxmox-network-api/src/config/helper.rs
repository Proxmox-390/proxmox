use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::sync::LazyLock;

use anyhow::{Context, Error, bail, format_err};
use const_format::concatcp;
use regex::Regex;

use proxmox_network_types::mac_address::MacAddress;
use proxmox_schema::api_types::IPV4RE_STR;
use proxmox_schema::api_types::IPV6RE_STR;

use crate::config::PHYSICAL_NIC_REGEX;

pub static IPV4_REVERSE_MASK: &[&str] = &[
    "0.0.0.0",
    "128.0.0.0",
    "192.0.0.0",
    "224.0.0.0",
    "240.0.0.0",
    "248.0.0.0",
    "252.0.0.0",
    "254.0.0.0",
    "255.0.0.0",
    "255.128.0.0",
    "255.192.0.0",
    "255.224.0.0",
    "255.240.0.0",
    "255.248.0.0",
    "255.252.0.0",
    "255.254.0.0",
    "255.255.0.0",
    "255.255.128.0",
    "255.255.192.0",
    "255.255.224.0",
    "255.255.240.0",
    "255.255.248.0",
    "255.255.252.0",
    "255.255.254.0",
    "255.255.255.0",
    "255.255.255.128",
    "255.255.255.192",
    "255.255.255.224",
    "255.255.255.240",
    "255.255.255.248",
    "255.255.255.252",
    "255.255.255.254",
    "255.255.255.255",
];

pub static IPV4_MASK_HASH_LOCALNET: LazyLock<HashMap<&'static str, u8>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    #[allow(clippy::needless_range_loop)]
    for i in 0..IPV4_REVERSE_MASK.len() {
        map.insert(IPV4_REVERSE_MASK[i], i as u8);
    }
    map
});

pub fn parse_cidr(cidr: &str) -> Result<(String, u8, bool), Error> {
    let (address, mask, is_v6) = parse_address_or_cidr(cidr)?;
    if let Some(mask) = mask {
        Ok((address, mask, is_v6))
    } else {
        bail!("missing netmask in '{}'", cidr);
    }
}

pub(crate) fn check_netmask(mask: u8, is_v6: bool) -> Result<(), Error> {
    let (ver, min, max) = if is_v6 {
        ("IPv6", 1, 128)
    } else {
        ("IPv4", 1, 32)
    };

    if !(mask >= min && mask <= max) {
        bail!(
            "{} mask '{}' is out of range ({}..{}).",
            ver,
            mask,
            min,
            max
        );
    }

    Ok(())
}

// parse ip address with optional cidr mask
pub(crate) fn parse_address_or_cidr(cidr: &str) -> Result<(String, Option<u8>, bool), Error> {
    // NOTE: This is NOT the same regex as in proxmox-schema as this one has capture groups for
    // the addresses vs cidr portions!
    pub static CIDR_V4_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(concatcp!(r"^(", IPV4RE_STR, r")(?:/(\d{1,2}))?$")).unwrap());
    pub static CIDR_V6_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(concatcp!(r"^(", IPV6RE_STR, r")(?:/(\d{1,3}))?$")).unwrap());

    if let Some(caps) = CIDR_V4_REGEX.captures(cidr) {
        let address = &caps[1];
        if let Some(mask) = caps.get(2) {
            let mask: u8 = mask.as_str().parse()?;
            check_netmask(mask, false)?;
            Ok((address.to_string(), Some(mask), false))
        } else {
            Ok((address.to_string(), None, false))
        }
    } else if let Some(caps) = CIDR_V6_REGEX.captures(cidr) {
        let address = &caps[1];
        if let Some(mask) = caps.get(2) {
            let mask: u8 = mask.as_str().parse()?;
            check_netmask(mask, true)?;
            Ok((address.to_string(), Some(mask), true))
        } else {
            Ok((address.to_string(), None, true))
        }
    } else {
        bail!("invalid address/mask '{}'", cidr);
    }
}

/// Struct representing the info_slave_data field inside link_info, as returned by `ip -details -json link show`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
pub struct SlaveData {
    perm_hw_addr: Option<MacAddress>,
}

/// Struct representing the link_info field, as returned by `ip -details -json link show`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
pub struct LinkInfo {
    info_slave_data: Option<SlaveData>,
    info_kind: Option<String>,
    #[serde(default, deserialize_with = "deserialize_info_data")]
    info_data: InfoData,
}

/// The `id` and `protocol` from the `info_data` of a link, e.g. of a VLAN interface.
#[derive(Debug, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct InfoData {
    id: Option<u64>,
    protocol: Option<String>,
}

/// Extracts the `id` and `protocol` from the `info_data` of a link.
///
/// The fields of `info_data` and their types depend on the kind of the link, e.g. `id` is the VNI
/// for VXLAN interfaces, so anything that does not fit is ignored instead of failing to parse the
/// whole link.
fn deserialize_info_data<'de, D>(deserializer: D) -> Result<InfoData, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let info_data: Option<serde_json::Value> = serde::Deserialize::deserialize(deserializer)?;

    Ok(InfoData {
        id: info_data.as_ref().and_then(|data| data.get("id")?.as_u64()),
        protocol: info_data
            .as_ref()
            .and_then(|data| Some(data.get("protocol")?.as_str()?.to_string())),
    })
}

impl LinkInfo {
    /// The attributes of the link as a port of its master device, e.g. a bond.
    pub fn info_slave_data(&self) -> Option<&SlaveData> {
        self.info_slave_data.as_ref()
    }

    /// The kind of the link, e.g. `bridge`, `vlan` or `wireguard`. Unset for physical interfaces.
    pub fn info_kind(&self) -> Option<&String> {
        self.info_kind.as_ref()
    }

    /// The VLAN ID of a VLAN interface.
    pub fn vlan_id(&self) -> Option<u16> {
        if self.info_kind.as_deref() != Some("vlan") {
            return None;
        }

        self.info_data.id.and_then(|id| u16::try_from(id).ok())
    }

    /// The protocol of a VLAN interface, `802.1Q` or `802.1ad`.
    pub fn vlan_protocol(&self) -> Option<&str> {
        if self.info_kind.as_deref() != Some("vlan") {
            return None;
        }

        self.info_data.protocol.as_deref()
    }
}

/// The fields specific to an interface of type `ether`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
pub struct EtherLink {
    address: MacAddress,
}

/// Catch all variant for all unknown link types.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
pub struct UnknownLink {
    // required, since otherwise the tagged enum will fail to parse, due to the tag of [`Link`]
    // being link_type.
    link_type: String,
}

/// Enum abstracting the fields that are specific to a given link type.
///
/// The JSON returned by `ip -details -json link show` returns different fields for different link
/// types. Depending on the type, fields with the same name can contain different types. This enum
/// is used to handle the fields that vary between the different link types.
///
/// The last variant is a catch all variant, that should capture everything else, so we do not get
/// deserialization errors in any case.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
#[serde(tag = "link_type", rename_all = "lowercase")]
pub enum Link {
    Ether(EtherLink),
    #[serde(untagged)]
    Unknown(UnknownLink),
}

/// A flag of a link, as listed in the `flags` field of `ip -details -json link show`.
///
/// Flags without a dedicated variant are kept as [`LinkFlag::Unknown`].
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinkFlag {
    Pointopoint,
    Noarp,
    Up,
    LowerUp,
    Broadcast,
    Multicast,
    Loopback,
    Promisc,
    #[serde(untagged)]
    Unknown(String),
}

/// An IpLink entry, as returned by `ip -details -json link show`.
///
/// For now this parses only the fields that are used throughout our stack, the fields of this
/// struct are incomplete. To abstract fields that are specific to a link type, this struct uses
/// [`Link`].
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde::Deserialize)]
pub struct IpLink {
    ifname: String,
    #[serde(default)]
    altnames: Vec<String>,
    ifindex: i64,
    #[serde(flatten)]
    link_type: Link,
    linkinfo: Option<LinkInfo>,
    operstate: String,
    #[serde(default)]
    flags: Vec<LinkFlag>,
    master: Option<String>,
    link: Option<String>,
}

impl IpLink {
    /// The index of the interface.
    pub fn index(&self) -> i64 {
        self.ifindex
    }

    /// Whether this is a physical or virtual interface.
    ///
    /// For ethernet interfaces, this checks whether info_kind is set in link_info,
    /// since virtual 'physical' interfaces (e.g. bridges) have link type ether as well.
    ///
    /// Otherwise, we fall back to [`PHYSICAL_NIC_REGEX`], which was the sole method for
    /// determining whether an interface is physical or not before. This should cover other types of
    /// non-ethernet physical interfaces (e.g. Infiniband), that have not been manually renamed.
    pub fn is_physical(&self) -> bool {
        if let Link::Ether(_) = self.link_type {
            if let Some(linkinfo) = &self.linkinfo {
                if linkinfo.info_kind.is_none() {
                    return true;
                }
            } else {
                return true;
            }
        }

        PHYSICAL_NIC_REGEX.is_match(&self.ifname)
    }

    /// The name of the interface (ifname / IFLA_IFNAME).
    pub fn name(&self) -> &str {
        &self.ifname
    }

    /// Returns the MAC address of the physical device, even if the interface is enslaved.
    ///
    /// Some interfaces can change their MAC address if they are enslaved to bonds or bridges. This
    /// method returns the permanent MAC address of a link, independent of whether they are
    /// enslaved or not.
    pub fn permanent_mac(&self) -> Option<MacAddress> {
        if let Link::Ether(ether) = &self.link_type {
            if let Some(link_info) = &self.linkinfo {
                if let Some(info_slave_data) = &link_info.info_slave_data {
                    return info_slave_data.perm_hw_addr;
                }
            }

            return Some(ether.address);
        }

        None
    }

    /// The [`LinkInfo`] for this link.
    pub fn linkinfo(&self) -> Option<&LinkInfo> {
        self.linkinfo.as_ref()
    }

    /// The operating state of the interface.
    pub fn operstate(&self) -> &str {
        &self.operstate
    }

    /// Returns an iterator over the altnames of an interface.
    pub fn altnames(&self) -> impl Iterator<Item = &String> {
        self.altnames.iter()
    }

    /// Returns the flags of this interface
    pub fn flags(&self) -> impl Iterator<Item = &LinkFlag> {
        self.flags.iter()
    }

    /// Returns whether the interface is currently in an UP state.
    pub fn active(&self) -> bool {
        self.operstate == "UP"
    }

    /// The name of the device this interface is enslaved to, e.g. a bridge, bond or VRF.
    pub fn master(&self) -> Option<&str> {
        self.master.as_deref()
    }

    /// The name of the device this interface is stacked on, e.g. the parent of a VLAN interface.
    pub fn link(&self) -> Option<&str> {
        self.link.as_deref()
    }
}

/// A mapping of altnames to the interfaces' ifname.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AltnameMapping {
    mapping: HashMap<String, String>,
}

impl std::ops::Deref for AltnameMapping {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.mapping
    }
}

impl FromIterator<IpLink> for AltnameMapping {
    fn from_iter<T: IntoIterator<Item = IpLink>>(iter: T) -> Self {
        let mut mapping = HashMap::new();

        for iface in iter.into_iter() {
            for altname in iface.altnames {
                mapping.insert(altname, iface.ifname.clone());
            }
        }

        Self { mapping }
    }
}

/// Returns a list of all network interfaces currently available on the host.
///
/// This parses the output of `ip -details -json link show` and returns a map of the ifname to the
/// [`IpLink`] for that interface.
pub fn get_network_interfaces() -> Result<HashMap<String, IpLink>, Error> {
    let output = std::process::Command::new("ip")
        .arg("-details")
        .arg("-json")
        .arg("link")
        .arg("show")
        .stdout(std::process::Stdio::piped())
        .output()
        .with_context(|| "could not obtain ip link output")?;

    if !output.status.success() {
        bail!("ip link returned non-zero exit code")
    }

    Ok(serde_json::from_slice::<Vec<IpLink>>(&output.stdout)
        .with_context(|| "could not deserialize ip link output")?
        .into_iter()
        .map(|ip_link| (ip_link.ifname.clone(), ip_link))
        .collect())
}

pub(crate) fn compute_file_diff(filename: &str, shadow: &str) -> Result<String, Error> {
    let output = Command::new("diff")
        .arg("-b")
        .arg("-u")
        .arg(filename)
        .arg(shadow)
        .output()
        .map_err(|err| format_err!("failed to execute diff - {}", err))?;

    let diff = proxmox_sys::command::command_output_as_string(output, Some(|c| c == 0 || c == 1))
        .map_err(|err| format_err!("diff failed: {}", err))?;

    Ok(diff)
}

pub fn assert_ifupdown2_installed() -> Result<(), Error> {
    if !Path::new("/usr/share/ifupdown2").exists() {
        bail!("ifupdown2 is not installed.");
    }

    Ok(())
}

pub fn network_reload() -> Result<(), Error> {
    let output = Command::new("ifreload")
        .arg("-a")
        .output()
        .map_err(|err| format_err!("failed to execute 'ifreload' - {}", err))?;

    proxmox_sys::command::command_output(output, None)
        .map_err(|err| format_err!("ifreload failed: {}", err))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_vlan_and_vxlan_interface() {
        let vlan = r#"{
    "ifindex": 9,
    "link": "vmbr0",
    "ifname": "vmbr0.100",
    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
    "operstate": "UP",
    "link_type": "ether",
    "address": "bc:24:11:e2:e1:01",
    "master": "vrf_zone1",
    "linkinfo": {
        "info_kind": "vlan",
        "info_data": { "protocol": "802.1Q", "id": 100, "flags": ["REORDER_HDR"] },
        "info_slave_kind": "vrf",
        "info_slave_data": { "table": 1001 }
    }
}"#;

        let link = serde_json::from_str::<IpLink>(vlan).unwrap();
        assert_eq!(link.link(), Some("vmbr0"));
        assert_eq!(link.linkinfo().and_then(LinkInfo::vlan_id), Some(100));
        assert_eq!(
            link.linkinfo().and_then(LinkInfo::vlan_protocol),
            Some("802.1Q")
        );

        let vxlan = r#"{
    "ifindex": 10,
    "ifname": "vxlan_vnet1",
    "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
    "operstate": "UNKNOWN",
    "link_type": "ether",
    "address": "8a:7f:0e:2b:45:61",
    "linkinfo": {
        "info_kind": "vxlan",
        "info_data": { "id": 100000, "local": "192.0.2.1", "port": 4789 }
    }
}"#;

        let link = serde_json::from_str::<IpLink>(vxlan).unwrap();
        assert_eq!(link.link(), None);
        assert_eq!(link.linkinfo().and_then(LinkInfo::vlan_id), None);
        assert_eq!(link.linkinfo().and_then(LinkInfo::vlan_protocol), None);
    }

    #[test]
    fn test_deserialize_ipv6_to_ipv4_tunnel() {
        let interface = r#"{
  "ifindex": 7,
  "link": null,
  "ifname": "sit0",
  "flags": [
    "NOARP"
  ],
  "mtu": 1480,
  "qdisc": "noop",
  "operstate": "DOWN",
  "linkmode": "DEFAULT",
  "group": "default",
  "txqlen": 1000,
  "link_type": "sit",
  "address": "0.0.0.0",
  "broadcast": "0.0.0.0",
  "promiscuity": 0,
  "allmulti": 0,
  "min_mtu": 1280,
  "max_mtu": 65555,
  "linkinfo": {
    "info_kind": "sit",
    "info_data": {
      "proto": "ip6ip",
      "remote": "any",
      "local": "any",
      "ttl": 64,
      "pmtudisc": false,
      "prefix": "2002::",
      "prefixlen": 16
    }
  },
  "inet6_addr_gen_mode": "eui64",
  "num_tx_queues": 1,
  "num_rx_queues": 1,
  "gso_max_size": 65536,
  "gso_max_segs": 65535,
  "tso_max_size": 65536,
  "tso_max_segs": 65535,
  "gro_max_size": 65536,
  "gso_ipv4_max_size": 65536,
  "gro_ipv4_max_size": 65536
}"#;

        let link = serde_json::from_str::<IpLink>(interface).unwrap();
        assert_eq!(link.master(), None);
    }

    #[test]
    fn test_deserialize_ethernet_interface() {
        let interface = r#"{
    "ifindex": 2,
    "ifname": "eth1",
    "flags": [
      "BROADCAST",
      "MULTICAST",
      "UP",
      "LOWER_UP"
    ],
    "mtu": 1500,
    "qdisc": "fq_codel",
    "master": "vmbr0",
    "operstate": "UP",
    "linkmode": "DEFAULT",
    "group": "default",
    "txqlen": 1000,
    "link_type": "ether",
    "address": "bc:24:11:ca:ff:ee",
    "broadcast": "ff:ff:ff:ff:ff:ff",
    "promiscuity": 1,
    "allmulti": 1,
    "min_mtu": 68,
    "max_mtu": 9194,
    "linkinfo": {
      "info_slave_kind": "bridge",
      "info_slave_data": {
        "state": "forwarding",
        "priority": 32,
        "cost": 5,
        "hairpin": false,
        "guard": false,
        "root_block": false,
        "fastleave": false,
        "learning": true,
        "flood": true,
        "id": "0x8001",
        "no": "0x1",
        "designated_port": 32769,
        "designated_cost": 0,
        "bridge_id": "8000.bc:24:11:00:00:00",
        "root_id": "8000.bc:24:11:00:00:00",
        "hold_timer": 0.00,
        "message_age_timer": 0.00,
        "forward_delay_timer": 0.00,
        "topology_change_ack": 0,
        "config_pending": 0,
        "proxy_arp": false,
        "proxy_arp_wifi": false,
        "multicast_router": 1,
        "mcast_flood": true,
        "bcast_flood": true,
        "mcast_to_unicast": false,
        "neigh_suppress": false,
        "neigh_vlan_suppress": false,
        "group_fwd_mask": "0",
        "group_fwd_mask_str": "0x0",
        "vlan_tunnel": false,
        "isolated": false,
        "locked": false,
        "mab": false
      }
    },
    "inet6_addr_gen_mode": "eui64",
    "num_tx_queues": 1,
    "num_rx_queues": 1,
    "gso_max_size": 64000,
    "gso_max_segs": 64,
    "tso_max_size": 64000,
    "tso_max_segs": 64,
    "gro_max_size": 65536,
    "gso_ipv4_max_size": 64000,
    "gro_ipv4_max_size": 65536,
    "parentbus": "pci",
    "parentdev": "0000:01:00.0",
    "altnames": [
      "enxbc2411aabbcc"
    ]
}"#;

        let link = serde_json::from_str::<IpLink>(interface).unwrap();
        assert_eq!(link.master(), Some("vmbr0"));
    }

    #[test]
    fn test_deserialize_tailscale_interface() {
        let interface = r#"{
    "ifindex": 3,
    "ifname": "tailscale0",
    "flags": [
      "POINTOPOINT",
      "MULTICAST",
      "NOARP",
      "UP",
      "LOWER_UP"
    ],
    "mtu": 1280,
    "qdisc": "fq_codel",
    "operstate": "UNKNOWN",
    "linkmode": "DEFAULT",
    "group": "default",
    "txqlen": 500,
    "link_type": "none",
    "promiscuity": 0,
    "allmulti": 0,
    "min_mtu": 68,
    "max_mtu": 65535,
    "linkinfo": {
      "info_kind": "tun",
      "info_data": {
        "type": "tun",
        "pi": false,
        "vnet_hdr": true,
        "multi_queue": false,
        "persist": false
      }
    },
    "inet6_addr_gen_mode": "random",
    "num_tx_queues": 1,
    "num_rx_queues": 1,
    "gso_max_size": 65536,
    "gso_max_segs": 65535,
    "tso_max_size": 65536,
    "tso_max_segs": 65535,
    "gro_max_size": 65536,
    "gso_ipv4_max_size": 65536,
    "gro_ipv4_max_size": 65536
}"#;

        serde_json::from_str::<IpLink>(interface).unwrap();
    }
}
