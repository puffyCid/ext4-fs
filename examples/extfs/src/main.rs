use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum, builder};
use csv::Writer;
use ext4_fs::{
    extfs::{Ext4Reader, Ext4ReaderAction},
    structs::{Ext4Hash, FileInfo, FileType, InodePermissions, InodeType},
};
use log::{LevelFilter, error};
use serde::Serialize;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, Write},
};
use std::{error::Error, fs};

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Path to ext4 filesystem
    #[clap(short, long)]
    input: Option<String>,

    /// Path to ext4 filesystem
    #[clap(short, long)]
    superblock: Option<String>,

    /// Output format. Options: csv
    #[clap(short, long, default_value = Format::Csv)]
    format: Format,

    /// MD5 files
    #[clap(long, default_value = "false")]
    md5: bool,

    /// SHA1 files
    #[clap(long, default_value = "false")]
    sha1: bool,

    /// SHA256 files
    #[clap(long, default_value = "false")]
    sha256: bool,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Format {
    Csv,
}

impl From<Format> for builder::OsStr {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv".into(),
        }
    }
}

impl From<Format> for &str {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv",
        }
    }
}

fn main() {
    TermLogger::init(
        LevelFilter::Warn,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Failed to initialize simple logger");

    let args = Args::parse();
    let output_format = args.format;

    if args.input.is_none() && args.superblock.is_none() {
        error!("Require a ext4 file to parse!");
        return;
    }

    if let Some(path) = args.input {
        let handle: Box<dyn Write> = Box::new(
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open("out.csv")
                .unwrap(),
        );
        let mut writer = OutputWriter::new(Box::new(handle), output_format.into()).unwrap();

        filesystem_reader(&path, args.md5, args.sha1, args.sha256, &mut writer);
    } else if let Some(path) = args.superblock {
        let reader = File::open(&path).unwrap();
        let buf = BufReader::new(reader);
        let mut ext_reader = Ext4Reader::new(buf, 4096).unwrap();
        let superblock = ext_reader.superblock().unwrap();
        println!("{superblock:?}");
    }
}

fn filesystem_reader(input: &str, md5: bool, sha1: bool, sha256: bool, writer: &mut OutputWriter) {
    let reader = File::open(input).unwrap();
    let buf = BufReader::new(reader);
    let mut ext_reader = Ext4Reader::new(buf, 4096).unwrap();

    let root = ext_reader.root().unwrap();
    let value = TimelineFiles {
        fullpath: String::from("/"),
        directory: String::from("/"),
        filename: String::from("/"),
        file_type: FileType::Directory,
        inode: 2,
        size: 0,
        permissions: root.permission.clone(),
        hard_links: root.hard_links,
        extended_attributes: root.extended_attributes.clone(),
        inode_type: root.inode_type,
        created: Utc
            .timestamp_nanos(root.created)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        modified: Utc
            .timestamp_nanos(root.modified)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        accessed: Utc
            .timestamp_nanos(root.accessed)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        changed: Utc
            .timestamp_nanos(root.changed)
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        deleted: Utc
            .timestamp_opt(root.deleted as i64, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        md5: String::new(),
        sha1: String::new(),
        sha256: String::new(),
    };
    let mut paths = Vec::new();
    paths.push(value);
    let mut cache = Vec::new();
    cache.push(String::from("/"));

    let hash = Ext4Hash { md5, sha1, sha256 };
    walk_dir(
        &root,
        &mut ext_reader,
        &mut cache,
        &hash,
        &mut paths,
        writer,
    );
    // Output remaining files
    if !paths.is_empty() {
        output(&paths, writer).unwrap();
    }
}

#[derive(Serialize)]
struct TimelineFiles {
    fullpath: String,
    directory: String,
    filename: String,
    file_type: FileType,
    inode: u64,
    size: u64,
    permissions: Vec<InodePermissions>,
    hard_links: u16,
    extended_attributes: HashMap<String, String>,
    inode_type: InodeType,
    created: String,
    modified: String,
    accessed: String,
    changed: String,
    deleted: String,
    md5: String,
    sha1: String,
    sha256: String,
}

fn walk_dir<T: std::io::Seek + std::io::Read>(
    info: &FileInfo,
    reader: &mut Ext4Reader<T>,
    cache: &mut Vec<String>,
    hash: &Ext4Hash,
    paths: &mut Vec<TimelineFiles>,
    writer: &mut OutputWriter,
) {
    for entry in &info.children {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        if paths.len() == 1000 {
            output(paths, writer).unwrap();
            paths.clear();
        }

        let info = reader.stat(entry.inode).unwrap();
        assert_ne!(info.inode, 0);

        if entry.file_type == FileType::Directory
            && entry.name != "."
            && entry.name != ".."
            && entry.inode != 2
        {
            let info = reader.read_dir(entry.inode).unwrap();
            let directory = cache.join("/").replace("//", "/");
            cache.push(info.name.clone());

            let value = TimelineFiles {
                fullpath: cache.join("/").replace("//", "/"),
                directory,
                filename: info.name.clone(),
                file_type: FileType::Directory,
                inode: info.inode,
                size: 0,
                permissions: info.permission.clone(),
                hard_links: info.hard_links,
                extended_attributes: info.extended_attributes.clone(),
                inode_type: info.inode_type,
                created: Utc
                    .timestamp_nanos(info.created)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                modified: Utc
                    .timestamp_nanos(info.modified)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                accessed: Utc
                    .timestamp_nanos(info.accessed)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                changed: Utc
                    .timestamp_nanos(info.changed)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                deleted: Utc
                    .timestamp_opt(info.deleted as i64, 0)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                md5: String::new(),
                sha1: String::new(),
                sha256: String::new(),
            };
            paths.push(value);
            walk_dir(&info, reader, cache, hash, paths, writer);
            cache.pop();
            continue;
        }

        println!(
            "Current file path: {}/{}",
            cache.join("/").replace("//", "/"),
            entry.name
        );

        // Hash files
        if entry.file_type == FileType::File {
            let hash_value = reader.hash(entry.inode, hash).unwrap();

            let directory = cache.join("/").replace("//", "/");

            let value = TimelineFiles {
                fullpath: format!("{}/{}", cache.join("/"), entry.name).replace("//", "/"),
                directory,
                filename: entry.name.clone(),
                file_type: FileType::File,
                inode: info.inode,
                size: info.size,
                permissions: info.permission,
                hard_links: info.hard_links,
                extended_attributes: info.extended_attributes,
                inode_type: info.inode_type,
                created: Utc
                    .timestamp_nanos(info.created)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                modified: Utc
                    .timestamp_nanos(info.modified)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                accessed: Utc
                    .timestamp_nanos(info.accessed)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                changed: Utc
                    .timestamp_nanos(info.changed)
                    .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
                deleted: Utc
                    .timestamp_opt(info.deleted as i64, 0)
                    .unwrap()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                md5: hash_value.md5,
                sha1: hash_value.sha1,
                sha256: hash_value.sha256,
            };
            paths.push(value);

            continue;
        }

        // Everything. Symbolic links, Blocks, FIFO, etc
        let directory = cache.join("/").replace("//", "/");
        let value = TimelineFiles {
            fullpath: format!("{}/{}", cache.join("/"), entry.name).replace("//", "/"),
            directory,
            filename: entry.name.clone(),
            file_type: entry.file_type,
            inode: info.inode,
            size: 0,
            permissions: info.permission,
            hard_links: info.hard_links,
            extended_attributes: info.extended_attributes,
            inode_type: info.inode_type,
            created: Utc
                .timestamp_nanos(info.created)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            modified: Utc
                .timestamp_nanos(info.modified)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            accessed: Utc
                .timestamp_nanos(info.accessed)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            changed: Utc
                .timestamp_nanos(info.changed)
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            deleted: Utc
                .timestamp_opt(info.deleted as i64, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            md5: String::new(),
            sha1: String::new(),
            sha256: String::new(),
        };
        paths.push(value);
    }
}

struct OutputWriter {
    writer: OutputWriterEnum,
}

enum OutputWriterEnum {
    Csv(Box<Writer<Box<dyn Write>>>),
}

impl OutputWriter {
    fn new(writer: Box<dyn Write>, output_format: &str) -> Result<Self, Box<dyn Error>> {
        let writer_enum = match output_format {
            "csv" => {
                let mut csv_writer = Writer::from_writer(writer);
                // Write CSV headers
                csv_writer.write_record([
                    "Full Path",
                    "Directory",
                    "Filename",
                    "File Type",
                    "Inode",
                    "Size",
                    "Permissions",
                    "Hard Links",
                    "Inode Type",
                    "Extended Attributes",
                    "Created",
                    "Modified",
                    "Accessed",
                    "Changed",
                    "Deleted",
                    "MD5",
                    "SHA1",
                    "SHA256",
                ])?;
                csv_writer.flush()?;
                OutputWriterEnum::Csv(Box::new(csv_writer))
            }
            _ => {
                error!("Unsupported output format: {output_format}");
                std::process::exit(1);
            }
        };

        Ok(OutputWriter {
            writer: writer_enum,
        })
    }

    fn write_record(&mut self, record: &TimelineFiles) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => {
                csv_writer.write_record(&[
                    record.fullpath.clone(),
                    record.directory.clone(),
                    record.filename.clone(),
                    format!("{:?}", record.file_type),
                    record.inode.to_string(),
                    record.size.to_string(),
                    format!("{:?}", record.permissions.clone()),
                    record.hard_links.to_string(),
                    format!("{:?}", record.inode_type),
                    format!("{:?}", record.extended_attributes),
                    record.created.clone(),
                    record.modified.clone(),
                    record.accessed.clone(),
                    record.changed.clone(),
                    record.deleted.clone(),
                    record.md5.clone(),
                    record.sha1.clone(),
                    record.sha256.clone(),
                ])?;
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => csv_writer.flush()?,
        }
        Ok(())
    }
}

// Append or create csv file
fn output(results: &Vec<TimelineFiles>, writer: &mut OutputWriter) -> Result<(), Box<dyn Error>> {
    for data in results {
        writer.write_record(data)?;
    }
    writer.flush()?;
    Ok(())
}
