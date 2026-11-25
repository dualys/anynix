use clap::ValueEnum;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TargetOs {
    Linux,
    FreeBsd,
    OpenBsd,
    Haiku,
}

pub fn substitute(script: &str, target: TargetOs) -> String {
    let (prefix, bin, lib, etc) = match target {
        TargetOs::Linux | TargetOs::FreeBsd | TargetOs::OpenBsd => (
            "/usr/local",
            "/usr/local/bin",
            "/usr/local/lib",
            "/usr/local/etc",
        ),
        TargetOs::Haiku => (
            "/boot/system",
            "/boot/system/bin",
            "/boot/system/lib",
            "/boot/system/settings",
        ),
    };
    script
        .replace("%bin%", bin)
        .replace("%lib%", lib)
        .replace("%etc%", etc)
        .replace("%prefix%", prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_for_all_targets() {
        for target in [TargetOs::Linux, TargetOs::FreeBsd, TargetOs::OpenBsd] {
            assert_eq!(
                substitute("%prefix% %bin% %lib% %etc%", target),
                "/usr/local /usr/local/bin /usr/local/lib /usr/local/etc"
            );
        }
        assert_eq!(
            substitute("%prefix% %bin% %lib% %etc%", TargetOs::Haiku),
            "/boot/system /boot/system/bin /boot/system/lib /boot/system/settings"
        );
    }
}
