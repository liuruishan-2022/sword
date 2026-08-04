use clap::Parser;

#[derive(Parser, Debug)]
#[command(author,version,about,long_about = None)]
pub struct LoadOptions {
    #[arg(long, short = 'c')]
    command: String,
}
