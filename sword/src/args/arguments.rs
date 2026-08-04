use clap::Parser;

#[derive(Parser, Debug)]
#[command(author,version,about,long_about = None)]
pub struct LoadOptions {
    #[arg(long, short = 'c')]
    command: String,
}

#[cfg(test)]
mod tests {
    use super::LoadOptions;
    use clap::Parser;

    #[test]
    fn parses_target_pid() {
        let options = LoadOptions::try_parse_from(["sword", "--target-pid", "42"]).unwrap();

        assert_eq!(options.target_pid, Some(42));
        assert_eq!(options.target_name, None);
    }

    #[test]
    fn parses_target_name() {
        let options =
            LoadOptions::try_parse_from(["sword", "--target-name", "ccm-server"]).unwrap();

        assert_eq!(options.target_pid, None);
        assert_eq!(options.target_name.as_deref(), Some("ccm-server"));
    }

    #[test]
    fn rejects_pid_and_name_together() {
        let result = LoadOptions::try_parse_from([
            "sword",
            "--target-pid",
            "42",
            "--target-name",
            "ccm-server",
        ]);

        assert!(result.is_err());
    }
}
