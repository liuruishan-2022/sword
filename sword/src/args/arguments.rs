use std::fs;

use clap::Parser;
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(author,version,about,long_about = None)]
pub struct LoadOptions {
    #[arg(long, short = 'c')]
    command: String,
}

impl LoadOptions {
    pub fn first_target_pid(&self) -> Option<u32> {
        return self.target_pid().into_iter().next();
    }

    ///
    /// 根据command获取到pid
    ///
    pub fn target_pid(&self) -> Vec<u32> {
        return WalkDir::new("/proc")
            .min_depth(1)
            .max_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|ele| !ele.file_type().is_dir())
            .filter_map(|ele| {
                ele.file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
            })
            .filter_map(|ele| self.cmdline_contains(ele))
            .collect::<Vec<u32>>();
    }

    fn cmdline_contains(&self, pid: u32) -> Option<u32> {
        let cmdline_path = format!("/poc/{pid}/cmdline");
        let Ok(cmdline) = fs::read(cmdline_path) else {
            return None;
        };

        let result = cmdline
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .any(|argument| String::from_utf8_lossy(argument).contains(self.command.as_str()));
        if result {
            return Some(pid);
        }
        return None;
    }
}
