//! Linux TCP counters, read from `/proc` before and after each run.
//!
//! The counters are system-wide, so traffic from other processes on this machine is included in
//! the deltas too. On other platforms nothing is read and the counters are reported as missing.

/// The TCP counters that help tell a lost SYN from slow server work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpCounters {
    /// Segments retransmitted (`Tcp: RetransSegs`).
    pub retrans_segs: u64,
    /// SYN packets retransmitted (`TcpExt: TCPSynRetrans`).
    pub syn_retrans: u64,
    /// Retransmission timeouts (`TcpExt: TCPTimeouts`).
    pub timeouts: u64,
}

impl TcpCounters {
    /// The change since `before`. Counters only grow, so a decrease (a counter reset) gives zero.
    pub fn since(self, before: TcpCounters) -> TcpCounters {
        TcpCounters {
            retrans_segs: self.retrans_segs.saturating_sub(before.retrans_segs),
            syn_retrans: self.syn_retrans.saturating_sub(before.syn_retrans),
            timeouts: self.timeouts.saturating_sub(before.timeouts),
        }
    }
}

/// Read the counters now. `None` if `/proc` is not available or does not have the fields.
pub fn read() -> Option<TcpCounters> {
    let snmp = std::fs::read_to_string("/proc/net/snmp").ok()?;
    let netstat = std::fs::read_to_string("/proc/net/netstat").ok()?;
    parse(&snmp, &netstat)
}

fn parse(snmp: &str, netstat: &str) -> Option<TcpCounters> {
    Some(TcpCounters {
        retrans_segs: field(snmp, "Tcp:", "RetransSegs")?,
        syn_retrans: field(netstat, "TcpExt:", "TCPSynRetrans")?,
        timeouts: field(netstat, "TcpExt:", "TCPTimeouts")?,
    })
}

/// Value of `name` in one section of a `/proc/net/*` file. Each section has a header line with
/// the field names and a line with the values, both starting with the section name.
fn field(text: &str, section: &str, name: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|line| line.starts_with(section));
    let names = lines.next()?;
    let values = lines.next()?;
    let index = names.split_whitespace().position(|n| n == name)?;
    values.split_whitespace().nth(index)?.parse().ok()
}

/// Error and drop counters of one network interface, from `/sys/class/net/<name>/statistics`.
/// They are system-wide for that interface, so they include all traffic on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NicCounters {
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub rx_missed: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

impl NicCounters {
    /// The change since `before`, never negative.
    pub fn since(self, before: NicCounters) -> NicCounters {
        NicCounters {
            rx_errors: self.rx_errors.saturating_sub(before.rx_errors),
            rx_dropped: self.rx_dropped.saturating_sub(before.rx_dropped),
            rx_missed: self.rx_missed.saturating_sub(before.rx_missed),
            tx_errors: self.tx_errors.saturating_sub(before.tx_errors),
            tx_dropped: self.tx_dropped.saturating_sub(before.tx_dropped),
        }
    }

    pub fn any(self) -> bool {
        self != NicCounters::default()
    }
}

/// Read the counters of `iface`. `None` if the interface has no statistics here.
pub fn read_nic(iface: &str) -> Option<NicCounters> {
    let base = format!("/sys/class/net/{iface}/statistics");
    let get = |name: &str| -> Option<u64> {
        std::fs::read_to_string(format!("{base}/{name}"))
            .ok()?
            .trim()
            .parse()
            .ok()
    };
    Some(NicCounters {
        rx_errors: get("rx_errors")?,
        rx_dropped: get("rx_dropped")?,
        rx_missed: get("rx_missed_errors")?,
        tx_errors: get("tx_errors")?,
        tx_dropped: get("tx_dropped")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNMP: &str = "Ip: Forwarding DefaultTTL\nIp: 1 64\nTcp: ActiveOpens RetransSegs OutSegs\nTcp: 5 42 1000\nUdp: InDatagrams\nUdp: 7\n";
    const NETSTAT: &str = "TcpExt: SyncookiesSent TCPTimeouts TCPSynRetrans\nTcpExt: 0 3 9\nIpExt: InNoRoutes\nIpExt: 0\n";

    #[test]
    fn parses_fields_by_name_not_position() {
        assert_eq!(
            parse(SNMP, NETSTAT),
            Some(TcpCounters {
                retrans_segs: 42,
                syn_retrans: 9,
                timeouts: 3,
            })
        );
    }

    #[test]
    fn missing_field_gives_none() {
        assert_eq!(parse("Tcp: ActiveOpens\nTcp: 5\n", NETSTAT), None);
        assert_eq!(parse(SNMP, "TcpExt: TCPTimeouts\nTcpExt: 3\n"), None);
    }

    #[test]
    fn section_names_do_not_match_prefixes() {
        // "TcpExt:" must not be read as "Tcp:".
        assert_eq!(field(NETSTAT, "Tcp:", "TCPTimeouts"), None);
    }

    #[test]
    fn delta_is_difference() {
        let before = TcpCounters {
            retrans_segs: 10,
            syn_retrans: 2,
            timeouts: 1,
        };
        let after = TcpCounters {
            retrans_segs: 13,
            syn_retrans: 3,
            timeouts: 1,
        };
        assert_eq!(
            after.since(before),
            TcpCounters {
                retrans_segs: 3,
                syn_retrans: 1,
                timeouts: 0
            }
        );
    }

    #[test]
    fn counter_reset_gives_zero_not_underflow() {
        let before = TcpCounters {
            retrans_segs: 10,
            syn_retrans: 2,
            timeouts: 1,
        };
        let after = TcpCounters {
            retrans_segs: 0,
            syn_retrans: 0,
            timeouts: 0,
        };
        assert_eq!(after.since(before).retrans_segs, 0);
    }

    #[test]
    fn reads_this_machine_when_available() {
        // Only checks the real files parse where they exist; elsewhere `read` may return None.
        if std::path::Path::new("/proc/net/netstat").exists() {
            assert!(read().is_some());
        }
    }
}
