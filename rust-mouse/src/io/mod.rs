pub mod file;

pub fn io_file() {
    let path = "/media/data/code/github/linux";
    file::line_count(path);
}
