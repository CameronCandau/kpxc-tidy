use std::{
    collections::{HashMap, HashSet},
    env, fs,
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

use chrono::{DateTime, TimeDelta, Utc};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, Gauge, List, ListItem, ListState, Paragraph, Wrap},
};
use serde::Deserialize;
use serde_json::Value;

const DEFAULT_ARCHIVE_GROUP: &str = "Archive/AutoCleanup";
const PASSKEY_DIRECTORY_URL: &str = "https://passkeys-api.2fa.directory/v1/supported.json";

type AppResult<T> = Result<T, AppError>;
type TuiTerminal = Terminal<CrosstermBackend<io::Stdout>>;

#[derive(Debug)]
enum AppError {
    Io(io::Error),
    Keepass(String),
    Xml(String),
    Args(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Keepass(msg) | Self::Xml(msg) | Self::Args(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<io::Error> for AppError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Entry {
    group_path: String,
    title: String,
    username: String,
    url: String,
    notes: String,
    uuid: String,
    last_mod: Option<DateTime<Utc>>,
    tags: String,
    has_attachment: bool,
    attachment_names: Vec<String>,
    custom_field_keys: Vec<String>,
    public_key_values: Vec<String>,
}

impl Entry {
    fn entry_path(&self) -> String {
        if self.group_path.is_empty() {
            self.title.clone()
        } else {
            format!("{}/{}", self.group_path, self.title)
        }
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Group {
    path: String,
    name: String,
    notes: String,
    last_mod: Option<DateTime<Utc>>,
    is_recycle_bin: bool,
    parent_path: String,
    direct_entries: Vec<usize>,
    subgroups: Vec<String>,
}

#[derive(Clone, Debug)]
struct AppConfig {
    database: String,
    stale_years: i64,
    recycle_days: i64,
    archive_group: String,
    preview_rows: usize,
    passkey_directory: Option<String>,
    read_only: bool,
    report_path: Option<String>,
}

#[derive(Debug)]
struct App {
    config: AppConfig,
    password: String,
    groups: HashMap<String, Group>,
    entries: Vec<Entry>,
    passkey_directory: Option<PasskeyDirectory>,
    screen: Screen,
    selected: usize,
    focus: Focus,
    pending: Option<PendingAction>,
    message: Option<Message>,
    progress: Option<ApplyProgress>,
    should_quit: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Focus {
    Audits,
    Findings,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Screen {
    Overview,
    EmptyGroups,
    Duplicates,
    Stale,
    RecycleBin,
    TitleCase,
    MissingUrl,
    Passkeys,
    Ssh,
}

impl Screen {
    const ALL: [Screen; 9] = [
        Screen::Overview,
        Screen::EmptyGroups,
        Screen::Duplicates,
        Screen::Stale,
        Screen::RecycleBin,
        Screen::TitleCase,
        Screen::MissingUrl,
        Screen::Passkeys,
        Screen::Ssh,
    ];

    fn label(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::EmptyGroups => "Empty groups",
            Screen::Duplicates => "Duplicates",
            Screen::Stale => "Stale entries",
            Screen::RecycleBin => "Recycle bin",
            Screen::TitleCase => "Title case",
            Screen::MissingUrl => "Missing URL",
            Screen::Passkeys => "Passkeys",
            Screen::Ssh => "SSH",
        }
    }

    fn action_hint(self) -> &'static str {
        match self {
            Screen::Overview => "r refresh | q quit",
            Screen::EmptyGroups => "x remove empty groups | r refresh | q quit",
            Screen::Duplicates => {
                "a archive older identity duplicates | d delete older identity duplicates | q quit"
            }
            Screen::Stale => "a archive stale entries | d delete stale entries | q quit",
            Screen::RecycleBin => {
                "p purge old entries | g purge empty groups | e native empty info | q quit"
            }
            Screen::TitleCase => "t update title-case candidates | q quit",
            Screen::MissingUrl => "report only | q quit",
            Screen::Passkeys => "f fetch/refresh directory | report only | q quit",
            Screen::Ssh => "report only | q quit",
        }
    }
}

#[derive(Debug)]
enum PendingAction {
    RemoveEmptyGroups(Vec<Group>),
    ArchiveIdentityDuplicates(Vec<Entry>),
    DeleteIdentityDuplicates(Vec<Entry>),
    ArchiveStale(Vec<Entry>),
    DeleteStale(Vec<Entry>),
    PurgeRecycleBin(Vec<Entry>),
    PurgeRecycleBinEmptyGroups(Vec<Group>),
    ApplyTitleCase(Vec<(Entry, String)>),
}

impl PendingAction {
    fn title(&self) -> &'static str {
        match self {
            Self::RemoveEmptyGroups(_) => "Remove empty groups?",
            Self::ArchiveIdentityDuplicates(_) => "Archive older duplicates?",
            Self::DeleteIdentityDuplicates(_) => "Delete older duplicates?",
            Self::ArchiveStale(_) => "Archive stale entries?",
            Self::DeleteStale(_) => "Delete stale entries?",
            Self::PurgeRecycleBin(_) => "Permanently purge recycle-bin entries?",
            Self::PurgeRecycleBinEmptyGroups(_) => "Permanently purge recycle-bin empty groups?",
            Self::ApplyTitleCase(_) => "Apply title-case updates?",
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::RemoveEmptyGroups(groups) => format!("Remove {} empty groups.", groups.len()),
            Self::ArchiveIdentityDuplicates(entries) => {
                format!(
                    "Move {} older URL+username duplicates into the archive group.",
                    entries.len()
                )
            }
            Self::DeleteIdentityDuplicates(entries) => {
                format!("Delete {} older URL+username duplicates.", entries.len())
            }
            Self::ArchiveStale(entries) => {
                format!(
                    "Move {} stale entries into the archive group.",
                    entries.len()
                )
            }
            Self::DeleteStale(entries) => format!("Delete {} stale entries.", entries.len()),
            Self::PurgeRecycleBin(entries) => {
                format!(
                    "Permanently remove {} old recycle-bin entries.",
                    entries.len()
                )
            }
            Self::PurgeRecycleBinEmptyGroups(groups) => {
                format!(
                    "Permanently remove {} empty groups inside the recycle bin.",
                    groups.len()
                )
            }
            Self::ApplyTitleCase(items) => format!("Update titles for {} entries.", items.len()),
        }
    }
}

#[derive(Debug)]
struct Message {
    title: String,
    body: String,
}

#[derive(Debug)]
struct ApplyProgress {
    title: String,
    total: usize,
    current: usize,
    changed: usize,
    phase: String,
    current_item: String,
    recent: Vec<String>,
}

#[derive(Debug)]
struct PasskeyDirectory {
    sites: HashMap<String, PasskeySite>,
    supported_domains: HashSet<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct PasskeySite {
    name: Option<String>,
    domain: Option<String>,
    url: Option<String>,
    documentation: Option<String>,
    passwordless: Option<PasskeySupport>,
    mfa: Option<PasskeySupport>,
    #[serde(default, rename = "additional-domains")]
    additional_domains: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PasskeySupport {
    Allowed,
    Unsupported,
    Other(String),
}

impl<'de> Deserialize<'de> for PasskeySupport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Ok(match value {
            Value::Bool(true) => Self::Allowed,
            Value::Bool(false) => Self::Unsupported,
            Value::String(value) if value.eq_ignore_ascii_case("allowed") => Self::Allowed,
            Value::String(value) if value.eq_ignore_ascii_case("unsupported") => Self::Unsupported,
            Value::String(value) => Self::Other(value),
            other => Self::Other(other.to_string()),
        })
    }
}

fn main() -> AppResult<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("{}", usage());
        return Ok(());
    }

    let mut config = parse_args(args)?;
    if config.passkey_directory.is_none()
        && let Some(path) = existing_default_passkey_directory()
    {
        config.passkey_directory = Some(path);
    }
    let password = rpassword::prompt_password(format!("Password for {}: ", config.database))?;
    let passkey_directory = load_passkey_directory(config.passkey_directory.as_deref())?;

    let mut app = App {
        config,
        password,
        groups: HashMap::new(),
        entries: Vec::new(),
        passkey_directory,
        screen: Screen::Overview,
        selected: 0,
        focus: Focus::Audits,
        pending: None,
        message: None,
        progress: None,
        should_quit: false,
    };

    eprintln!("Loading database model...");
    load_database(&mut app)?;
    if let Some(report_path) = app.config.report_path.as_deref() {
        fs::write(report_path, render_markdown_report(&app))?;
        eprintln!("Wrote report to {report_path}");
        return Ok(());
    }
    eprintln!("Loaded database model. Starting TUI...");
    run_tui(&mut app)
}

fn parse_args(args: Vec<String>) -> AppResult<AppConfig> {
    if args.is_empty() {
        return Err(AppError::Args(usage()));
    }

    let mut database = None;
    let mut stale_years = 3;
    let mut recycle_days = 30;
    let mut archive_group = DEFAULT_ARCHIVE_GROUP.to_string();
    let mut preview_rows = 50;
    let mut passkey_directory = None;
    let mut read_only = false;
    let mut report_path = None;
    let mut idx = 0;

    while idx < args.len() {
        match args[idx].as_str() {
            "--stale-years" => {
                idx += 1;
                stale_years = parse_i64_arg(&args, idx, "--stale-years")?;
            }
            "--recycle-days" => {
                idx += 1;
                recycle_days = parse_i64_arg(&args, idx, "--recycle-days")?;
            }
            "--archive-group" => {
                idx += 1;
                archive_group = args
                    .get(idx)
                    .ok_or_else(|| AppError::Args("Missing value for --archive-group".to_string()))?
                    .clone();
            }
            "--preview-rows" => {
                idx += 1;
                preview_rows = parse_usize_arg(&args, idx, "--preview-rows")?;
            }
            "--passkey-directory" => {
                idx += 1;
                passkey_directory = Some(
                    args.get(idx)
                        .ok_or_else(|| {
                            AppError::Args("Missing value for --passkey-directory".to_string())
                        })?
                        .clone(),
                );
            }
            "--read-only" => {
                read_only = true;
            }
            "--report" => {
                idx += 1;
                report_path = Some(
                    args.get(idx)
                        .ok_or_else(|| AppError::Args("Missing value for --report".to_string()))?
                        .clone(),
                );
            }
            value if value.starts_with('-') => {
                return Err(AppError::Args(format!(
                    "Unknown option: {value}\n\n{}",
                    usage()
                )));
            }
            value => {
                if database.replace(value.to_string()).is_some() {
                    return Err(AppError::Args(format!(
                        "Only one database path is supported.\n\n{}",
                        usage()
                    )));
                }
            }
        }
        idx += 1;
    }

    let database = database.ok_or_else(|| AppError::Args(usage()))?;
    if stale_years <= 0 || recycle_days <= 0 || preview_rows == 0 {
        return Err(AppError::Args(
            "Thresholds and preview rows must be positive.".to_string(),
        ));
    }

    Ok(AppConfig {
        database,
        stale_years,
        recycle_days,
        archive_group,
        preview_rows,
        passkey_directory,
        read_only,
        report_path,
    })
}

fn parse_i64_arg(args: &[String], idx: usize, option: &str) -> AppResult<i64> {
    args.get(idx)
        .ok_or_else(|| AppError::Args(format!("Missing value for {option}")))?
        .parse()
        .map_err(|_| AppError::Args(format!("Expected integer for {option}")))
}

fn parse_usize_arg(args: &[String], idx: usize, option: &str) -> AppResult<usize> {
    args.get(idx)
        .ok_or_else(|| AppError::Args(format!("Missing value for {option}")))?
        .parse()
        .map_err(|_| AppError::Args(format!("Expected integer for {option}")))
}

fn usage() -> String {
    "Usage: kpxc-tidy <database.kdbx> [--read-only] [--report report.md] [--stale-years N] [--recycle-days N] [--archive-group PATH] [--preview-rows N] [--passkey-directory supported.json]".to_string()
}

fn run_tui(app: &mut App) -> AppResult<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_tui_loop(app, &mut terminal);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn load_passkey_directory(path: Option<&str>) -> AppResult<Option<PasskeyDirectory>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let text = fs::read_to_string(path)
        .map_err(|err| AppError::Args(format!("Failed to read passkey directory {path}: {err}")))?;
    let sites: HashMap<String, PasskeySite> = serde_json::from_str(&text).map_err(|err| {
        AppError::Args(format!(
            "Failed to parse passkey directory JSON {path}: {err}"
        ))
    })?;
    let mut supported_domains = HashSet::new();
    for (key, site) in &sites {
        if looks_like_domain(key) {
            supported_domains.insert(key.to_lowercase());
        }
        if let Some(domain) = &site.domain
            && looks_like_domain(domain)
        {
            supported_domains.insert(domain.to_lowercase());
        }
        for domain in &site.additional_domains {
            if looks_like_domain(domain) {
                supported_domains.insert(domain.to_lowercase());
            }
        }
    }
    Ok(Some(PasskeyDirectory {
        sites,
        supported_domains,
    }))
}

fn fetch_passkey_directory(app: &mut App, terminal: &mut TuiTerminal) -> AppResult<()> {
    let path = app
        .config
        .passkey_directory
        .clone()
        .unwrap_or(default_passkey_directory_path()?);
    let tmp_path = format!("{path}.tmp");

    set_apply_progress(
        app,
        "Passkey directory".to_string(),
        2,
        0,
        0,
        "Downloading",
        PASSKEY_DIRECTORY_URL,
        &[],
    );
    redraw(terminal, app)?;

    let path_buf = PathBuf::from(&path);
    if let Some(parent) = path_buf.parent() {
        fs::create_dir_all(parent)?;
    }

    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
            &tmp_path,
            PASSKEY_DIRECTORY_URL,
        ])
        .output()
        .map_err(|err| {
            AppError::Args(format!(
                "Failed to run curl. Install curl or use --passkey-directory with a downloaded supported.json file. {err}"
            ))
        })?;

    if !output.status.success() {
        let _ = fs::remove_file(&tmp_path);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AppError::Args(if stderr.is_empty() {
            "Failed to download passkey directory with curl.".to_string()
        } else {
            stderr
        }));
    }

    set_apply_progress(
        app,
        "Passkey directory".to_string(),
        2,
        1,
        0,
        "Parsing",
        &path,
        &[],
    );
    redraw(terminal, app)?;

    fs::rename(&tmp_path, &path)?;
    app.config.passkey_directory = Some(path.clone());
    app.passkey_directory = load_passkey_directory(Some(&path))?;
    app.progress = None;
    set_message(
        app,
        "Passkey Directory",
        format!("Downloaded and loaded passkey support data from {PASSKEY_DIRECTORY_URL}."),
    );
    Ok(())
}

fn existing_default_passkey_directory() -> Option<String> {
    let path = default_passkey_directory_path().ok()?;
    PathBuf::from(&path).exists().then_some(path)
}

fn default_passkey_directory_path() -> AppResult<String> {
    let base = if let Some(cache_home) = env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(cache_home)
    } else {
        let home = env::var_os("HOME").ok_or_else(|| {
            AppError::Args(
                "No HOME or XDG_CACHE_HOME set; use --passkey-directory supported.json."
                    .to_string(),
            )
        })?;
        PathBuf::from(home).join(".cache")
    };
    Ok(base
        .join("kpxc-tidy")
        .join("passkeys-supported.json")
        .to_string_lossy()
        .to_string())
}

fn run_tui_loop(app: &mut App, terminal: &mut TuiTerminal) -> AppResult<()> {
    while !app.should_quit {
        terminal.draw(|frame| draw(frame, app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
        {
            handle_key(app, key, terminal)?;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent, terminal: &mut TuiTerminal) -> AppResult<()> {
    if app.message.is_some() {
        app.message = None;
        return Ok(());
    }

    if app.pending.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => apply_pending(app, terminal)?,
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => app.pending = None,
            _ => {}
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Tab => {
            app.focus = if app.focus == Focus::Audits {
                Focus::Findings
            } else {
                Focus::Audits
            };
        }
        KeyCode::Left | KeyCode::Char('h') => {
            app.focus = Focus::Audits;
        }
        KeyCode::Right | KeyCode::Char('l') => {
            app.focus = Focus::Findings;
            clamp_selected(app);
        }
        KeyCode::Enter => {
            if app.focus == Focus::Findings {
                if let Some(detail) = selected_finding_detail(app) {
                    set_message(app, detail.title, detail.body);
                } else {
                    set_message(
                        app,
                        "Finding Detail",
                        "No selectable finding on this screen.",
                    );
                }
            }
        }
        KeyCode::Char('w') => {
            let path = default_report_path();
            fs::write(&path, render_markdown_report(app))?;
            set_message(
                app,
                "Report Export",
                format!("Wrote Markdown report to {path}."),
            );
        }
        KeyCode::Char('r') => {
            refresh_database(app, terminal)?;
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.focus == Focus::Findings {
                move_selected(app, 1);
            } else {
                app.screen = next_screen(app.screen);
                app.selected = 0;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.focus == Focus::Findings {
                move_selected(app, -1);
            } else {
                app.screen = previous_screen(app.screen);
                app.selected = 0;
            }
        }
        KeyCode::Char('x') if app.screen == Screen::EmptyGroups => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let groups = find_empty_groups(&app.groups);
            if groups.is_empty() {
                set_message(app, "Empty groups", "No empty groups found.");
            } else {
                app.pending = Some(PendingAction::RemoveEmptyGroups(groups));
            }
        }
        KeyCode::Char('a') if app.screen == Screen::Duplicates => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries = duplicate_identity_action_entries(&app.entries);
            if entries.is_empty() {
                set_message(
                    app,
                    "Duplicates",
                    "No URL+username duplicate entries to archive.",
                );
            } else {
                app.pending = Some(PendingAction::ArchiveIdentityDuplicates(entries));
            }
        }
        KeyCode::Char('d') if app.screen == Screen::Duplicates => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries = duplicate_identity_action_entries(&app.entries);
            if entries.is_empty() {
                set_message(
                    app,
                    "Duplicates",
                    "No URL+username duplicate entries to delete.",
                );
            } else {
                app.pending = Some(PendingAction::DeleteIdentityDuplicates(entries));
            }
        }
        KeyCode::Char('a') if app.screen == Screen::Stale => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries = find_stale_entries(&app.entries, app.config.stale_years);
            if entries.is_empty() {
                set_message(app, "Stale entries", "No stale entries found.");
            } else {
                app.pending = Some(PendingAction::ArchiveStale(entries));
            }
        }
        KeyCode::Char('d') if app.screen == Screen::Stale => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries = find_stale_entries(&app.entries, app.config.stale_years);
            if entries.is_empty() {
                set_message(app, "Stale entries", "No stale entries found.");
            } else {
                app.pending = Some(PendingAction::DeleteStale(entries));
            }
        }
        KeyCode::Char('p') if app.screen == Screen::RecycleBin => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries =
                find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days);
            if entries.is_empty() {
                set_message(app, "Recycle bin", "No old recycle-bin entries found.");
            } else {
                app.pending = Some(PendingAction::PurgeRecycleBin(entries));
            }
        }
        KeyCode::Char('g') if app.screen == Screen::RecycleBin => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let groups = find_empty_recycle_bin_groups(&app.groups);
            if groups.is_empty() {
                set_message(app, "Recycle bin", "No empty recycle-bin groups found.");
            } else {
                app.pending = Some(PendingAction::PurgeRecycleBinEmptyGroups(groups));
            }
        }
        KeyCode::Char('e') if app.screen == Screen::RecycleBin => {
            set_message(
                app,
                "Native Empty Recycle Bin",
                "This installed keepassxc-cli does not expose a native empty-recycle-bin command. It only supports rm for entries and rmdir for groups. kpxc-tidy will not treat rmdir on the recycle-bin root as native empty because that could remove the special recycle-bin group itself.",
            );
        }
        KeyCode::Char('t') if app.screen == Screen::TitleCase => {
            if app.config.read_only {
                show_read_only_message(app);
                return Ok(());
            }
            let entries = find_title_case_candidates(&app.entries);
            if entries.is_empty() {
                set_message(app, "Title case", "No title-case candidates found.");
            } else {
                app.pending = Some(PendingAction::ApplyTitleCase(entries));
            }
        }
        KeyCode::Char('f') if app.screen == Screen::Passkeys => {
            if let Err(err) = fetch_passkey_directory(app, terminal) {
                app.progress = None;
                set_message(app, "Passkey Directory", err.to_string());
            }
        }
        _ => {}
    }
    Ok(())
}

fn set_message(app: &mut App, title: impl Into<String>, body: impl Into<String>) {
    app.message = Some(Message {
        title: title.into(),
        body: body.into(),
    });
}

fn show_read_only_message(app: &mut App) {
    set_message(
        app,
        "Read-only Mode",
        "This session was started with --read-only, so actions that modify the vault are disabled.",
    );
}

fn refresh_database(app: &mut App, terminal: &mut TuiTerminal) -> AppResult<()> {
    set_apply_progress(
        app,
        "Refresh database".to_string(),
        1,
        0,
        0,
        "Exporting",
        "Reloading the database model from keepassxc-cli.",
        &[],
    );
    redraw(terminal, app)?;

    match load_database(app) {
        Ok(()) => {
            app.progress = None;
            app.message = Some(Message {
                title: "Refreshed".to_string(),
                body: "Database state reloaded from keepassxc-cli export.".to_string(),
            });
            Ok(())
        }
        Err(err) => {
            app.progress = None;
            Err(err)
        }
    }
}

#[derive(Debug)]
struct FindingDetail {
    title: String,
    body: String,
}

fn move_selected(app: &mut App, delta: isize) {
    let count = selectable_findings(app).len();
    if count == 0 {
        app.selected = 0;
        return;
    }
    let current = app.selected.min(count - 1) as isize;
    let next = (current + delta).clamp(0, count as isize - 1);
    app.selected = next as usize;
}

fn clamp_selected(app: &mut App) {
    let count = selectable_findings(app).len();
    if count == 0 {
        app.selected = 0;
    } else {
        app.selected = app.selected.min(count - 1);
    }
}

fn selected_finding_detail(app: &App) -> Option<FindingDetail> {
    selectable_findings(app).into_iter().nth(app.selected)
}

fn selectable_findings(app: &App) -> Vec<FindingDetail> {
    match app.screen {
        Screen::Overview => Vec::new(),
        Screen::EmptyGroups => find_empty_groups(&app.groups)
            .into_iter()
            .map(|group| group_detail("Empty Group", &group))
            .collect(),
        Screen::Duplicates => duplicate_finding_details(app),
        Screen::Stale => find_stale_entries(&app.entries, app.config.stale_years)
            .into_iter()
            .map(|entry| entry_detail("Stale Entry", &entry))
            .collect(),
        Screen::RecycleBin => recycle_finding_details(app),
        Screen::TitleCase => find_title_case_candidates(&app.entries)
            .into_iter()
            .map(|(entry, new_title)| FindingDetail {
                title: "Title Case Candidate".to_string(),
                body: format!(
                    "{}\n\nProposed title: {new_title}",
                    entry_detail_text(&entry)
                ),
            })
            .collect(),
        Screen::MissingUrl => find_entries_missing_url(&app.entries)
            .into_iter()
            .map(|entry| entry_detail("Missing URL", &entry))
            .collect(),
        Screen::Passkeys => passkey_finding_details(app),
        Screen::Ssh => find_ssh_entries(&app.entries)
            .into_iter()
            .map(|entry| {
                let summary = ssh_summary(&entry);
                FindingDetail {
                    title: "SSH Entry".to_string(),
                    body: format!("{}\n\nSSH summary: {summary}", entry_detail_text(&entry)),
                }
            })
            .collect(),
    }
}

fn entry_detail(title: &str, entry: &Entry) -> FindingDetail {
    FindingDetail {
        title: title.to_string(),
        body: entry_detail_text(entry),
    }
}

fn entry_detail_text(entry: &Entry) -> String {
    format!(
        "Path: {}\nUUID: {}\nUsername: {}\nURL: {}\nModified: {}\nTags: {}\nAttachments: {}\nCustom fields: {}\nNotes present: {}",
        entry.entry_path(),
        entry.uuid,
        entry.username,
        entry.url,
        fmt_dt(entry.last_mod),
        empty_dash(&entry.tags),
        list_or_dash(&entry.attachment_names),
        list_or_dash(&entry.custom_field_keys),
        !entry.notes.trim().is_empty()
    )
}

fn group_detail(title: &str, group: &Group) -> FindingDetail {
    FindingDetail {
        title: title.to_string(),
        body: format!(
            "Path: {}\nParent: {}\nModified: {}\nSubgroups: {}\nDirect entries: {}\nNotes present: {}",
            group.path,
            empty_dash(&group.parent_path),
            fmt_dt(group.last_mod),
            group.subgroups.len(),
            group.direct_entries.len(),
            !group.notes.trim().is_empty()
        ),
    }
}

fn duplicate_finding_details(app: &App) -> Vec<FindingDetail> {
    let mut details = Vec::new();
    for cluster in sorted_duplicate_clusters(find_duplicates_by_title(&app.entries)) {
        for entry in cluster {
            details.push(entry_detail("Duplicate Title Entry", &entry));
        }
    }
    for cluster in sorted_duplicate_clusters(find_duplicates_by_identity(&app.entries)) {
        for (idx, entry) in cluster.iter().enumerate() {
            let title = if idx == 0 {
                "Duplicate Identity Entry: Keep Newest"
            } else {
                "Duplicate Identity Entry: Candidate"
            };
            details.push(entry_detail(title, entry));
        }
    }
    details
}

fn recycle_finding_details(app: &App) -> Vec<FindingDetail> {
    let mut details: Vec<FindingDetail> =
        find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days)
            .into_iter()
            .map(|entry| entry_detail("Old Recycle-Bin Entry", &entry))
            .collect();
    details.extend(
        find_empty_recycle_bin_groups(&app.groups)
            .into_iter()
            .map(|group| group_detail("Empty Recycle-Bin Group", &group)),
    );
    details
}

fn passkey_finding_details(app: &App) -> Vec<FindingDetail> {
    let mut details: Vec<FindingDetail> = find_entries_with_passkeys(&app.entries)
        .into_iter()
        .map(|entry| entry_detail("Detected Passkey Entry", &entry))
        .collect();
    details.extend(find_supported_passkey_candidates(app).into_iter().map(
        |(entry, site_domain, site)| FindingDetail {
            title: "Supported Passkey Candidate".to_string(),
            body: format!(
                "{}\n\nSupported site: {}\nMode: {}\nDetail: {}",
                entry_detail_text(&entry),
                site_label(&site_domain, &site),
                passkey_support_mode(&site),
                empty_dash(&passkey_site_detail(&site))
            ),
        },
    ));
    details
}

fn empty_dash(value: &str) -> String {
    if value.trim().is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

fn list_or_dash(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(", ")
    }
}

fn default_report_path() -> String {
    format!("kpxc-tidy-report-{}.md", Utc::now().format("%Y%m%d-%H%M%S"))
}

fn render_markdown_report(app: &App) -> String {
    let mut out = String::new();
    push_report_line(&mut out, "# kpxc-tidy report");
    push_report_line(&mut out, "");
    push_report_line(&mut out, &format!("- Database: `{}`", app.config.database));
    push_report_line(&mut out, &format!("- Entries: {}", app.entries.len()));
    push_report_line(&mut out, &format!("- Groups: {}", app.groups.len()));
    push_report_line(
        &mut out,
        &format!("- Generated UTC: {}", Utc::now().to_rfc3339()),
    );
    push_report_line(
        &mut out,
        &format!("- Read-only mode: {}", app.config.read_only),
    );
    push_report_line(&mut out, "");

    push_report_section(
        &mut out,
        "Empty Groups",
        find_empty_groups(&app.groups)
            .iter()
            .map(|group| format!("- `{}`", group.path))
            .collect(),
    );

    let title_clusters = sorted_duplicate_clusters(find_duplicates_by_title(&app.entries));
    let identity_clusters = sorted_duplicate_clusters(find_duplicates_by_identity(&app.entries));
    push_report_line(&mut out, "## Duplicates");
    push_report_line(&mut out, "");
    push_report_line(
        &mut out,
        &format!("- Duplicate title clusters: {}", title_clusters.len()),
    );
    push_report_line(
        &mut out,
        &format!(
            "- Duplicate URL+username clusters: {}",
            identity_clusters.len()
        ),
    );
    push_report_line(&mut out, "");
    for cluster in title_clusters.iter().take(app.config.preview_rows) {
        if let Some(entry) = cluster.first() {
            push_report_line(
                &mut out,
                &format!("### Title `{}` in `{}`", entry.title, entry.group_path),
            );
            for entry in cluster {
                push_report_line(&mut out, &format!("- {}", report_entry_summary(entry)));
            }
            push_report_line(&mut out, "");
        }
    }
    for cluster in identity_clusters.iter().take(app.config.preview_rows) {
        if let Some(entry) = cluster.first() {
            push_report_line(
                &mut out,
                &format!("### URL `{}` username `{}`", entry.url, entry.username),
            );
            for (idx, entry) in cluster.iter().enumerate() {
                let marker = if idx == 0 { "keep-newest" } else { "candidate" };
                push_report_line(
                    &mut out,
                    &format!("- `{marker}` {}", report_entry_summary(entry)),
                );
            }
            push_report_line(&mut out, "");
        }
    }

    push_report_section(
        &mut out,
        "Stale Entries",
        find_stale_entries(&app.entries, app.config.stale_years)
            .iter()
            .take(app.config.preview_rows)
            .map(report_entry_summary)
            .map(|line| format!("- {line}"))
            .collect(),
    );

    push_report_section(&mut out, "Recycle Bin", recycle_report_lines(app));

    push_report_section(
        &mut out,
        "Missing URL",
        find_entries_missing_url(&app.entries)
            .iter()
            .take(app.config.preview_rows)
            .map(report_entry_summary)
            .map(|line| format!("- {line}"))
            .collect(),
    );

    push_report_section(&mut out, "Passkeys", passkey_report_lines(app));

    push_report_section(
        &mut out,
        "SSH",
        find_ssh_entries(&app.entries)
            .iter()
            .take(app.config.preview_rows)
            .map(|entry| format!("- {} | {}", report_entry_summary(entry), ssh_summary(entry)))
            .collect(),
    );

    out
}

fn push_report_section(out: &mut String, title: &str, lines: Vec<String>) {
    push_report_line(out, &format!("## {title}"));
    push_report_line(out, "");
    if lines.is_empty() {
        push_report_line(out, "_No findings._");
    } else {
        for line in lines {
            push_report_line(out, &line);
        }
    }
    push_report_line(out, "");
}

fn push_report_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn report_entry_summary(entry: &Entry) -> String {
    format!(
        "`{}` | user `{}` | url `{}` | modified `{}`{}",
        entry.entry_path(),
        entry.username,
        entry.url,
        fmt_dt(entry.last_mod),
        entry_flags(entry)
    )
}

fn recycle_report_lines(app: &App) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days)
        .iter()
        .take(app.config.preview_rows)
    {
        lines.push(format!("- old entry {}", report_entry_summary(entry)));
    }
    for group in find_empty_recycle_bin_groups(&app.groups)
        .iter()
        .take(app.config.preview_rows)
    {
        lines.push(format!(
            "- empty group `{}` | modified `{}`",
            group.path,
            fmt_dt(group.last_mod)
        ));
    }
    lines
}

fn passkey_report_lines(app: &App) -> Vec<String> {
    let mut lines = Vec::new();
    for entry in find_entries_with_passkeys(&app.entries)
        .iter()
        .take(app.config.preview_rows)
    {
        lines.push(format!("- detected {}", report_entry_summary(entry)));
    }
    for (entry, site_domain, site) in find_supported_passkey_candidates(app)
        .iter()
        .take(app.config.preview_rows)
    {
        lines.push(format!(
            "- candidate {} | supports `{}` | mode `{}`",
            report_entry_summary(entry),
            site_label(site_domain, site),
            passkey_support_mode(site)
        ));
    }
    lines
}

fn next_screen(screen: Screen) -> Screen {
    let idx = Screen::ALL
        .iter()
        .position(|item| *item == screen)
        .unwrap_or(0);
    Screen::ALL[(idx + 1) % Screen::ALL.len()]
}

fn previous_screen(screen: Screen) -> Screen {
    let idx = Screen::ALL
        .iter()
        .position(|item| *item == screen)
        .unwrap_or(0);
    Screen::ALL[(idx + Screen::ALL.len() - 1) % Screen::ALL.len()]
}

fn draw(frame: &mut Frame, app: &App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    draw_header(frame, app, outer[0]);
    draw_body(frame, app, outer[1]);
    draw_footer(frame, app, outer[2]);

    if let Some(pending) = &app.pending {
        draw_confirm(frame, pending);
    }

    if let Some(message) = &app.message {
        draw_message(frame, message);
    }

    if let Some(progress) = &app.progress {
        draw_progress(frame, progress);
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let title = Line::from(vec![
        Span::styled("kpxc-tidy", Style::new().bold().fg(Color::Cyan)),
        Span::raw("  "),
        Span::raw(&app.config.database),
    ]);
    let paragraph = Paragraph::new(title)
        .block(Block::default().borders(Borders::BOTTOM))
        .alignment(Alignment::Left);
    frame.render_widget(paragraph, area);
}

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(40)])
        .split(area);

    let audit_active = app.focus == Focus::Audits;
    let items: Vec<ListItem> = Screen::ALL
        .iter()
        .map(|screen| {
            let count = audit_count(app, *screen);
            let style = if *screen == app.screen {
                if audit_active {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                }
            } else {
                Style::default()
            };
            let label = match screen {
                Screen::Overview => Line::from(vec![
                    Span::styled("  ", style),
                    Span::styled(screen.label(), style),
                ]),
                _ => Line::from(vec![
                    Span::styled("  ", style),
                    Span::styled(format!("{:<17}", screen.label()), style),
                    Span::styled(format!("{count:>3}"), metric_style(count)),
                ]),
            };
            ListItem::new(label).style(style)
        })
        .collect();
    let audits_block = Block::default()
        .title(pane_title("Audits", audit_active))
        .borders(Borders::ALL)
        .border_style(pane_border_style(audit_active));
    let list = List::new(items).block(audits_block).highlight_symbol("> ");
    let mut state = ListState::default();
    state.select(Some(
        Screen::ALL
            .iter()
            .position(|screen| *screen == app.screen)
            .unwrap_or(0),
    ));
    frame.render_stateful_widget(list, columns[0], &mut state);

    let text = detail_text(app);
    let detail = Paragraph::new(text)
        .block(
            Block::default()
                .title(detail_title(app))
                .borders(Borders::ALL)
                .border_style(pane_border_style(app.focus == Focus::Findings)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(detail, columns[1]);
}

fn screen_report_text(app: &App) -> Text<'static> {
    match app.screen {
        Screen::Overview => overview_text(app),
        Screen::EmptyGroups => empty_groups_text(app),
        Screen::Duplicates => duplicates_text(app),
        Screen::Stale => stale_text(app),
        Screen::RecycleBin => recycle_text(app),
        Screen::TitleCase => title_case_text(app),
        Screen::MissingUrl => missing_url_text(app),
        Screen::Passkeys => passkey_text(app),
        Screen::Ssh => ssh_text(app),
    }
}

fn detail_text(app: &App) -> Text<'static> {
    if app.focus != Focus::Findings {
        return screen_report_text(app);
    }

    let findings = selectable_findings(app);
    let Some(detail) = findings.get(app.selected.min(findings.len().saturating_sub(1))) else {
        let mut lines = vec![
            Line::from("No selectable findings on this screen.").fg(Color::DarkGray),
            Line::raw(""),
            Line::from("Press Tab or h/← to return to the audit list.").fg(Color::DarkGray),
            Line::raw(""),
            Line::from("Report"),
            Line::raw(""),
        ];
        lines.extend(screen_report_text(app).lines);
        return Text::from(lines);
    };

    let mut lines = vec![
        Line::from(format!(
            "Selected finding {} of {}",
            app.selected.min(findings.len() - 1) + 1,
            findings.len()
        ))
        .style(Style::new().bold().fg(Color::Cyan)),
        Line::from(detail.title.clone()).style(Style::new().bold()),
        Line::raw(""),
    ];
    lines.extend(detail.body.lines().map(|line| Line::from(line.to_string())));
    lines.push(Line::raw(""));
    lines.push(
        Line::from("Press Enter for a larger detail view. Press Tab or h/← to return to audits.")
            .fg(Color::DarkGray),
    );
    lines.push(Line::raw(""));
    lines.push(Line::from("Report").style(Style::new().bold()));
    lines.push(Line::raw(""));
    lines.extend(screen_report_text(app).lines);
    Text::from(lines)
}

fn detail_title(app: &App) -> String {
    if app.focus == Focus::Findings {
        let count = selectable_findings(app).len();
        if count == 0 {
            format!("{} findings [active, none]", app.screen.label())
        } else {
            format!(
                "{} findings [active {}/{}]",
                app.screen.label(),
                app.selected.min(count - 1) + 1,
                count
            )
        }
    } else {
        pane_title(app.screen.label(), false)
    }
}

fn pane_title(title: &str, active: bool) -> String {
    if active {
        format!("{title} [active]")
    } else {
        title.to_string()
    }
}

fn pane_border_style(active: bool) -> Style {
    if active {
        Style::new().fg(Color::Cyan)
    } else {
        Style::new().fg(Color::DarkGray)
    }
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let mode = if app.config.read_only {
        "read-only | "
    } else {
        ""
    };
    let focus = match app.focus {
        Focus::Audits => "focus audits",
        Focus::Findings => "focus findings",
    };
    let text = format!(
        "{mode}{focus} | Tab switch focus | h/← audits | l/→ findings | ↑/k ↓/j move | Enter detail | w write report | {} | Esc/n cancel | y confirm",
        app.screen.action_hint()
    );
    frame.render_widget(Paragraph::new(text).fg(Color::DarkGray), area);
}

fn draw_confirm(frame: &mut Frame, pending: &PendingAction) {
    let area = centered_rect(68, 30, frame.area());
    frame.render_widget(Clear, area);
    let text = Text::from(vec![
        Line::from(pending.title()).style(Style::new().bold().fg(Color::Yellow)),
        Line::raw(""),
        Line::from(pending.summary()),
        Line::raw(""),
        Line::from("Press y to apply, n or Esc to cancel.").fg(Color::DarkGray),
    ]);
    let block = Block::default().title("Confirm").borders(Borders::ALL);
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_message(frame: &mut Frame, message: &Message) {
    let area = centered_rect(70, 34, frame.area());
    frame.render_widget(Clear, area);
    let text = Text::from(vec![
        Line::from(message.title.as_str()).style(Style::new().bold().fg(Color::Cyan)),
        Line::raw(""),
        Line::from(message.body.as_str()),
        Line::raw(""),
        Line::from("Press any key to continue.").fg(Color::DarkGray),
    ]);
    let block = Block::default().title("Message").borders(Borders::ALL);
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_progress(frame: &mut Frame, progress: &ApplyProgress) {
    let area = centered_rect(74, 42, frame.area());
    frame.render_widget(Clear, area);

    let ratio = if progress.total == 0 {
        1.0
    } else {
        progress.current as f64 / progress.total as f64
    };
    let percent = (ratio * 100.0).round() as u16;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let gauge = Gauge::default()
        .block(Block::default().title("Applying").borders(Borders::ALL))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(ratio.clamp(0.0, 1.0))
        .label(format!(
            "{} of {} ({percent}%)",
            progress.current, progress.total
        ));
    frame.render_widget(gauge, chunks[0]);

    let mut lines = vec![
        Line::from(progress.title.as_str()).style(Style::new().bold().fg(Color::Yellow)),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Changed: ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                progress.changed.to_string(),
                Style::new().bold().fg(Color::Green),
            ),
            Span::raw("   "),
            Span::styled("Phase: ", Style::new().fg(Color::DarkGray)),
            Span::styled(progress.phase.as_str(), Style::new().fg(Color::Yellow)),
        ]),
        Line::raw(""),
        Line::from(progress.current_item.as_str()),
        Line::raw(""),
        Line::from("Press c or Esc to stop after the current command finishes.")
            .fg(Color::DarkGray),
    ];

    if !progress.recent.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::from("Recent:").style(Style::new().bold()));
        for item in &progress.recent {
            lines.push(Line::from(format!("- {item}")));
        }
    }

    let block = Block::default().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM);
    frame.render_widget(
        Paragraph::new(Text::from(lines))
            .block(block)
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn overview_text(app: &App) -> Text<'static> {
    let duplicate_titles = find_duplicates_by_title(&app.entries).len();
    let duplicate_identity = find_duplicates_by_identity(&app.entries).len();
    let empty_groups = find_empty_groups(&app.groups).len();
    let stale = find_stale_entries(&app.entries, app.config.stale_years).len();
    let recycle =
        find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days).len();
    let title_case = find_title_case_candidates(&app.entries).len();
    let missing_url = find_entries_missing_url(&app.entries).len();
    let passkeys = find_entries_with_passkeys(&app.entries).len();
    let passkey_candidates = find_supported_passkey_candidates(app).len();
    let ssh = find_ssh_entries(&app.entries).len();

    Text::from(vec![
        Line::from(vec![
            Span::styled("Database: ", Style::new().bold()),
            Span::raw(app.config.database.clone()),
        ]),
        Line::raw(""),
        Line::from(format!("Entries: {}", app.entries.len())),
        Line::from(format!("Groups: {}", app.groups.len())),
        Line::raw(""),
        metric_line("Empty groups", empty_groups),
        metric_line("Duplicate title clusters", duplicate_titles),
        metric_line("Duplicate URL+username clusters", duplicate_identity),
        metric_line(
            format!("Stale entries > {} years", app.config.stale_years),
            stale,
        ),
        metric_line(
            format!(
                "Recycle-bin purge candidates > {} days",
                app.config.recycle_days
            ),
            recycle,
        ),
        metric_line("Title-case candidates", title_case),
        metric_line("Entries missing URL", missing_url),
        metric_line("Entries with detected passkeys", passkeys),
        metric_line("Supported passkey candidates", passkey_candidates),
        metric_line("SSH-looking entries", ssh),
        Line::raw(""),
        Line::from("Use ↑/↓ to inspect audit categories.").fg(Color::DarkGray),
    ])
}

fn audit_count(app: &App, screen: Screen) -> usize {
    match screen {
        Screen::Overview => 0,
        Screen::EmptyGroups => find_empty_groups(&app.groups).len(),
        Screen::Duplicates => {
            find_duplicates_by_title(&app.entries).len()
                + find_duplicates_by_identity(&app.entries).len()
        }
        Screen::Stale => find_stale_entries(&app.entries, app.config.stale_years).len(),
        Screen::RecycleBin => {
            find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days).len()
                + find_empty_recycle_bin_groups(&app.groups).len()
        }
        Screen::TitleCase => find_title_case_candidates(&app.entries).len(),
        Screen::MissingUrl => find_entries_missing_url(&app.entries).len(),
        Screen::Passkeys => {
            find_entries_with_passkeys(&app.entries).len()
                + find_supported_passkey_candidates(app).len()
        }
        Screen::Ssh => find_ssh_entries(&app.entries).len(),
    }
}

fn metric_line(label: impl Into<String>, count: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{:<38}", label.into()),
            Style::new().fg(Color::DarkGray),
        ),
        Span::styled(format!("{count:>5}"), metric_style(count)),
    ])
}

fn metric_style(count: usize) -> Style {
    if count == 0 {
        Style::new().fg(Color::DarkGray)
    } else {
        Style::new().bold().fg(Color::Yellow)
    }
}

fn empty_groups_text(app: &App) -> Text<'static> {
    let groups = find_empty_groups(&app.groups);
    if groups.is_empty() {
        return Text::from("No empty groups found.");
    }
    let mut lines = vec![
        Line::from(format!("Found {} empty groups.", groups.len())),
        Line::raw(""),
    ];
    for group in groups.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!("- {}", group.path)));
    }
    push_more(&mut lines, groups.len(), app.config.preview_rows);
    lines.push(Line::raw(""));
    lines.push(Line::from("Press x to remove these groups after confirmation.").fg(Color::Yellow));
    Text::from(lines)
}

fn duplicates_text(app: &App) -> Text<'static> {
    let title_clusters = sorted_duplicate_clusters(find_duplicates_by_title(&app.entries));
    let identity_clusters = sorted_duplicate_clusters(find_duplicates_by_identity(&app.entries));
    if title_clusters.is_empty() && identity_clusters.is_empty() {
        return Text::from("No duplicate-title or duplicate URL+username clusters found.");
    }

    let mut lines = vec![
        Line::from("Report only. Nothing changes unless you press a or d and confirm.")
            .fg(Color::DarkGray),
        Line::raw(""),
        Line::from(format!(
            "Duplicate title clusters: {}",
            title_clusters.len()
        ))
        .style(Style::new().bold()),
    ];

    let mut shown = 0;
    for cluster in title_clusters.iter().take(app.config.preview_rows) {
        if shown >= app.config.preview_rows {
            break;
        }
        if let Some(entry) = cluster.first() {
            lines.push(Line::from(format!(
                "- title={:?} group={} ({})",
                entry.title,
                entry.group_path,
                cluster.len()
            )));
            shown += 1;
        }
        for entry in cluster {
            if shown >= app.config.preview_rows {
                break;
            }
            lines.push(duplicate_entry_line("    ", "", entry));
            shown += 1;
        }
    }
    lines.push(Line::raw(""));
    lines.push(
        Line::from(format!(
            "Duplicate URL+username clusters: {}",
            identity_clusters.len()
        ))
        .style(Style::new().bold()),
    );
    shown = 0;
    for cluster in identity_clusters.iter().take(app.config.preview_rows) {
        if shown >= app.config.preview_rows {
            break;
        }
        if let Some(entry) = cluster.first() {
            lines.push(Line::from(format!(
                "- url={:?} user={:?} ({})",
                entry.url,
                entry.username,
                cluster.len()
            )));
            shown += 1;
        }
        for (idx, entry) in cluster.iter().enumerate() {
            if shown >= app.config.preview_rows {
                break;
            }
            let marker = if idx == 0 { "keep newest" } else { "candidate" };
            lines.push(duplicate_entry_line("    ", marker, entry));
            shown += 1;
        }
    }
    lines.push(Line::raw(""));
    lines.push(
        Line::from("Press a to archive older URL+username duplicates. Press d to delete.")
            .fg(Color::Yellow),
    );
    Text::from(lines)
}

fn duplicate_entry_line(indent: &str, marker: &str, entry: &Entry) -> Line<'static> {
    let marker = if marker.is_empty() {
        String::new()
    } else {
        format!(" [{marker}]")
    };
    Line::from(format!(
        "{indent}- {} | modified={}{}{}",
        entry.entry_path(),
        fmt_dt(entry.last_mod),
        marker,
        entry_flags(entry)
    ))
}

fn entry_flags(entry: &Entry) -> String {
    let mut flags = Vec::new();
    if !entry.notes.trim().is_empty() {
        flags.push("notes");
    }
    if !entry.tags.trim().is_empty() {
        flags.push("tags");
    }
    if entry.has_attachment {
        flags.push("attachment");
    }
    if flags.is_empty() {
        String::new()
    } else {
        format!(" | {}", flags.join(","))
    }
}

fn optional_detail(value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        format!(" | {value}")
    }
}

fn stale_text(app: &App) -> Text<'static> {
    let entries = find_stale_entries(&app.entries, app.config.stale_years);
    if entries.is_empty() {
        return Text::from(format!(
            "No entries older than {} years.",
            app.config.stale_years
        ));
    }
    let mut lines = vec![
        Line::from(format!(
            "Found {} entries older than {} years.",
            entries.len(),
            app.config.stale_years
        )),
        Line::raw(""),
    ];
    for entry in entries.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | modified={} | user={:?} | url={:?}",
            entry.entry_path(),
            fmt_dt(entry.last_mod),
            entry.username,
            entry.url
        )));
    }
    push_more(&mut lines, entries.len(), app.config.preview_rows);
    lines.push(Line::raw(""));
    lines.push(Line::from("Press a to archive, d to delete after confirmation.").fg(Color::Yellow));
    Text::from(lines)
}

fn recycle_text(app: &App) -> Text<'static> {
    let entries = find_old_recycle_entries(&app.groups, &app.entries, app.config.recycle_days);
    let empty_groups = find_empty_recycle_bin_groups(&app.groups);
    if entries.is_empty() && empty_groups.is_empty() {
        return Text::from(format!(
            "No recycle-bin entries older than {} days and no empty recycle-bin groups.",
            app.config.recycle_days
        ));
    }
    let mut lines = vec![
        Line::from(format!(
            "Old recycle-bin entry purge candidates: {}",
            entries.len()
        ))
        .style(Style::new().bold()),
        Line::raw(""),
    ];
    for entry in entries.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | modified={}",
            entry.entry_path(),
            fmt_dt(entry.last_mod)
        )));
    }
    push_more(&mut lines, entries.len(), app.config.preview_rows);
    lines.push(Line::raw(""));
    lines.push(
        Line::from(format!("Empty recycle-bin groups: {}", empty_groups.len()))
            .style(Style::new().bold()),
    );
    for group in empty_groups.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | modified={}",
            group.path,
            fmt_dt(group.last_mod)
        )));
    }
    push_more(&mut lines, empty_groups.len(), app.config.preview_rows);
    lines.push(Line::raw(""));
    lines.push(
        Line::from(
            "Press p to purge old entries, g to purge empty groups, e for native empty info.",
        )
        .fg(Color::Yellow),
    );
    Text::from(lines)
}

fn title_case_text(app: &App) -> Text<'static> {
    let entries = find_title_case_candidates(&app.entries);
    if entries.is_empty() {
        return Text::from("No title-case candidates found.");
    }
    let mut lines = vec![
        Line::from(format!("Found {} title-case candidates.", entries.len())),
        Line::raw(""),
    ];
    for (entry, new_title) in entries.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} -> {}",
            entry.entry_path(),
            new_title
        )));
    }
    push_more(&mut lines, entries.len(), app.config.preview_rows);
    lines.push(Line::raw(""));
    lines.push(Line::from("Press t to update titles after confirmation.").fg(Color::Yellow));
    Text::from(lines)
}

fn missing_url_text(app: &App) -> Text<'static> {
    let entries = find_entries_missing_url(&app.entries);
    if entries.is_empty() {
        return Text::from("No entries with a missing URL found.");
    }
    let mut lines = vec![
        Line::from(format!("Found {} entries missing a URL.", entries.len())),
        Line::from("This report is read-only for now.").fg(Color::DarkGray),
        Line::raw(""),
    ];
    for entry in entries.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | user={:?} | modified={}",
            entry.entry_path(),
            entry.username,
            fmt_dt(entry.last_mod)
        )));
    }
    push_more(&mut lines, entries.len(), app.config.preview_rows);
    Text::from(lines)
}

fn passkey_text(app: &App) -> Text<'static> {
    let with_passkeys = find_entries_with_passkeys(&app.entries);
    let candidates = find_supported_passkey_candidates(app);
    if with_passkeys.is_empty() && candidates.is_empty() {
        if app.passkey_directory.is_none() {
            return Text::from(
                "No passkey metadata found. Press f to download the public passkey support directory, or use --passkey-directory supported.json.",
            );
        }
        return Text::from("No passkey metadata or directory-supported passkey candidates found.");
    }

    let mut lines = vec![
        Line::from("Report only. Passkey support matching uses a local JSON directory file.")
            .fg(Color::DarkGray),
        Line::raw(""),
        Line::from(format!(
            "Entries with detected KeePassXC passkey metadata: {}",
            with_passkeys.len()
        ))
        .style(Style::new().bold()),
    ];

    for entry in with_passkeys.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | domain={} | modified={}{}",
            entry.entry_path(),
            entry_domain(entry).unwrap_or_else(|| "-".to_string()),
            fmt_dt(entry.last_mod),
            entry_flags(entry)
        )));
    }
    push_more(&mut lines, with_passkeys.len(), app.config.preview_rows);

    lines.push(Line::raw(""));
    if app.passkey_directory.is_none() {
        lines.push(
            Line::from("No passkey directory loaded. Press f to download it, or use --passkey-directory supported.json.")
                .fg(Color::DarkGray),
        );
        return Text::from(lines);
    }
    lines.push(
        Line::from(format!(
            "Directory-supported entries without detected passkeys: {}",
            candidates.len()
        ))
        .style(Style::new().bold()),
    );
    for (entry, site_domain, site) in candidates.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | entry_domain={} | supports={} | mode={} | user={:?}{}",
            entry.entry_path(),
            entry_domain(entry).unwrap_or_else(|| "-".to_string()),
            site_label(site_domain, site),
            passkey_support_mode(site),
            entry.username,
            optional_detail(&passkey_site_detail(site))
        )));
    }
    push_more(&mut lines, candidates.len(), app.config.preview_rows);

    Text::from(lines)
}

fn ssh_text(app: &App) -> Text<'static> {
    let entries = find_ssh_entries(&app.entries);
    if entries.is_empty() {
        return Text::from("No SSH-looking entries found.");
    }

    let mut lines = vec![
        Line::from("Report only. Use this as an SSH key inventory and review aid.")
            .fg(Color::DarkGray),
        Line::raw(""),
        Line::from(format!("SSH-looking entries: {}", entries.len())).style(Style::new().bold()),
    ];

    for entry in entries.iter().take(app.config.preview_rows) {
        lines.push(Line::from(format!(
            "- {} | {} | user={:?} | modified={}{}",
            entry.entry_path(),
            ssh_summary(entry),
            entry.username,
            fmt_dt(entry.last_mod),
            entry_flags(entry)
        )));
    }
    push_more(&mut lines, entries.len(), app.config.preview_rows);

    lines.push(Line::raw(""));
    lines.push(Line::from("Review legacy key types, missing public-key comments, and agent-heavy vaults manually.").fg(Color::DarkGray));
    Text::from(lines)
}

fn push_more(lines: &mut Vec<Line<'static>>, total: usize, shown: usize) {
    if total > shown {
        lines.push(Line::from(format!("... {} more", total - shown)));
    }
}

fn fmt_dt(value: Option<DateTime<Utc>>) -> String {
    value
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn load_database(app: &mut App) -> AppResult<()> {
    let output = run_keepassxc(&["export", "-q", &app.config.database], Some(&app.password))?;
    let (groups, entries) = build_model(&output)?;
    app.groups = groups;
    app.entries = entries;
    Ok(())
}

fn run_keepassxc(args: &[&str], password: Option<&str>) -> AppResult<String> {
    let keepassxc = env::var("KEEPASSXC_CLI").unwrap_or_else(|_| "keepassxc-cli".to_string());
    let mut child = Command::new(keepassxc)
        .args(args)
        .stdin(if password.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| AppError::Keepass(format!("Failed to start keepassxc-cli: {err}")))?;

    if let Some(password) = password
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(password.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let msg = if !stderr.is_empty() { stderr } else { stdout };
        return Err(AppError::Keepass(if msg.is_empty() {
            "keepassxc-cli command failed".to_string()
        } else {
            msg
        }));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn build_model(xml: &str) -> AppResult<(HashMap<String, Group>, Vec<Entry>)> {
    let doc = roxmltree::Document::parse(xml)
        .map_err(|err| AppError::Xml(format!("Failed to parse XML export: {err}")))?;
    let root = doc.root_element();
    let recycle_bin_uuid = child_text_path(root, &["Meta", "RecycleBinUUID"]).unwrap_or_default();
    let root_group = child_named(root, "Root")
        .and_then(|node| child_named(node, "Group"))
        .ok_or_else(|| AppError::Xml("No Root/Group found in KeePass XML export.".to_string()))?;

    let mut groups = HashMap::new();
    let mut entries = Vec::new();
    walk_group(root_group, "", &recycle_bin_uuid, &mut groups, &mut entries);
    Ok((groups, entries))
}

fn walk_group(
    group_node: roxmltree::Node<'_, '_>,
    parent_path: &str,
    recycle_bin_uuid: &str,
    groups: &mut HashMap<String, Group>,
    entries: &mut Vec<Entry>,
) {
    let group_name = child_text(group_node, "Name");
    let path = if parent_path.is_empty() {
        group_name.clone()
    } else {
        format!("{parent_path}/{group_name}")
    };
    let uuid = child_text(group_node, "UUID");
    let notes = child_text(group_node, "Notes");
    let last_mod = parse_timestamp(
        &child_text_path(group_node, &["Times", "LastModificationTime"]).unwrap_or_default(),
    );

    groups.insert(
        path.clone(),
        Group {
            path: path.clone(),
            name: group_name,
            notes,
            last_mod,
            is_recycle_bin: !recycle_bin_uuid.is_empty() && uuid == recycle_bin_uuid,
            parent_path: parent_path.to_string(),
            direct_entries: Vec::new(),
            subgroups: Vec::new(),
        },
    );

    for child in group_node.children().filter(|node| node.is_element()) {
        match child.tag_name().name() {
            "Entry" => {
                let index = entries.len();
                entries.push(parse_entry(child, &path));
                if let Some(group) = groups.get_mut(&path) {
                    group.direct_entries.push(index);
                }
            }
            "Group" => {
                let subgroup_name = child_text(child, "Name");
                let subgroup_path = if path.is_empty() {
                    subgroup_name
                } else {
                    format!("{path}/{subgroup_name}")
                };
                if let Some(group) = groups.get_mut(&path) {
                    group.subgroups.push(subgroup_path);
                }
                walk_group(child, &path, recycle_bin_uuid, groups, entries);
            }
            _ => {}
        }
    }
}

fn parse_entry(entry_node: roxmltree::Node<'_, '_>, group_path: &str) -> Entry {
    let mut strings: HashMap<String, String> = HashMap::new();
    let mut custom_field_keys = Vec::new();
    let mut public_key_values = Vec::new();
    for string_node in entry_node
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "String")
    {
        let key = child_text(string_node, "Key");
        let value = child_text(string_node, "Value");
        if is_custom_field_key(&key) {
            custom_field_keys.push(key.clone());
        }
        if looks_like_ssh_public_key(&value) || key.to_lowercase().contains("public") {
            public_key_values.push(value.clone());
        }
        strings.insert(key, value);
    }

    let attachment_names = attachment_names(entry_node);
    Entry {
        group_path: group_path.to_string(),
        title: strings.remove("Title").unwrap_or_default(),
        username: strings.remove("UserName").unwrap_or_default(),
        url: strings.remove("URL").unwrap_or_default(),
        notes: strings.remove("Notes").unwrap_or_default(),
        uuid: child_text(entry_node, "UUID"),
        last_mod: parse_timestamp(
            &child_text_path(entry_node, &["Times", "LastModificationTime"]).unwrap_or_default(),
        ),
        tags: child_text(entry_node, "Tags"),
        has_attachment: !attachment_names.is_empty()
            || child_named(entry_node, "Binaries").is_some()
            || child_named(entry_node, "Binary").is_some(),
        attachment_names,
        custom_field_keys,
        public_key_values,
    }
}

fn is_custom_field_key(key: &str) -> bool {
    !matches!(
        key,
        "Title" | "UserName" | "Password" | "URL" | "Notes" | "TOTP"
    )
}

fn attachment_names(entry_node: roxmltree::Node<'_, '_>) -> Vec<String> {
    entry_node
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Binary")
        .filter_map(|node| {
            let key = child_text(node, "Key");
            if key.is_empty() { None } else { Some(key) }
        })
        .collect()
}

fn child_named<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn child_text(node: roxmltree::Node<'_, '_>, name: &str) -> String {
    child_named(node, name)
        .and_then(|child| child.text())
        .unwrap_or_default()
        .to_string()
}

fn child_text_path(node: roxmltree::Node<'_, '_>, path: &[&str]) -> Option<String> {
    let mut current = node;
    for part in path {
        current = child_named(current, part)?;
    }
    Some(current.text().unwrap_or_default().to_string())
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            DateTime::parse_from_rfc3339(&value.replace('Z', "+00:00"))
                .map(|dt| dt.with_timezone(&Utc))
        })
        .ok()
}

fn collect_descendant_entry_count(groups: &HashMap<String, Group>, group_path: &str) -> usize {
    let Some(group) = groups.get(group_path) else {
        return 0;
    };
    let mut count = group.direct_entries.len();
    for subgroup in &group.subgroups {
        count += collect_descendant_entry_count(groups, subgroup);
    }
    count
}

fn find_empty_groups(groups: &HashMap<String, Group>) -> Vec<Group> {
    let recycle_path = find_recycle_bin_group(groups).map(|group| group.path);
    let mut results: Vec<Group> = groups
        .values()
        .filter(|group| {
            let in_recycle_bin = recycle_path
                .as_ref()
                .is_some_and(|path| group.path == *path || is_descendant_path(&group.path, path));
            !in_recycle_bin && collect_descendant_entry_count(groups, &group.path) == 0
        })
        .cloned()
        .collect();
    results.sort_by(|a, b| {
        b.path
            .matches('/')
            .count()
            .cmp(&a.path.matches('/').count())
            .then(a.path.cmp(&b.path))
    });
    results
}

fn find_duplicates_by_title(entries: &[Entry]) -> HashMap<String, Vec<Entry>> {
    let mut buckets: HashMap<String, Vec<Entry>> = HashMap::new();
    for entry in entries {
        let key = format!(
            "{}\0{}",
            entry.group_path.to_lowercase(),
            entry.title.to_lowercase()
        );
        buckets.entry(key).or_default().push(entry.clone());
    }
    buckets.retain(|_, bucket| bucket.len() > 1);
    buckets
}

fn find_duplicates_by_identity(entries: &[Entry]) -> HashMap<String, Vec<Entry>> {
    let mut buckets: HashMap<String, Vec<Entry>> = HashMap::new();
    for entry in entries {
        if entry.url.trim().is_empty() && entry.username.trim().is_empty() {
            continue;
        }
        let key = format!(
            "{}\0{}",
            entry.url.trim().to_lowercase(),
            entry.username.trim().to_lowercase()
        );
        buckets.entry(key).or_default().push(entry.clone());
    }
    buckets.retain(|_, bucket| bucket.len() > 1);
    buckets
}

fn sorted_duplicate_clusters(buckets: HashMap<String, Vec<Entry>>) -> Vec<Vec<Entry>> {
    let mut clusters: Vec<Vec<Entry>> = buckets.into_values().collect();
    for cluster in &mut clusters {
        cluster.sort_by(|a, b| {
            b.last_mod
                .cmp(&a.last_mod)
                .then(a.entry_path().cmp(&b.entry_path()))
        });
    }
    clusters.sort_by_key(|cluster| duplicate_cluster_key(cluster));
    clusters
}

fn duplicate_cluster_key(cluster: &[Entry]) -> String {
    cluster.first().map_or_else(String::new, |entry| {
        format!(
            "{}\0{}\0{}\0{}",
            entry.url.to_lowercase(),
            entry.username.to_lowercase(),
            entry.group_path.to_lowercase(),
            entry.title.to_lowercase()
        )
    })
}

fn duplicate_identity_action_entries(entries: &[Entry]) -> Vec<Entry> {
    let mut results = Vec::new();
    for cluster in sorted_duplicate_clusters(find_duplicates_by_identity(entries)) {
        for entry in cluster.into_iter().skip(1) {
            if !entry.title.trim().is_empty() {
                results.push(entry);
            }
        }
    }
    results
}

fn find_stale_entries(entries: &[Entry], years: i64) -> Vec<Entry> {
    let cutoff = Utc::now() - TimeDelta::days(365 * years);
    let mut results: Vec<Entry> = entries
        .iter()
        .filter(|entry| entry.last_mod.is_some_and(|last_mod| last_mod < cutoff))
        .cloned()
        .collect();
    results.sort_by(|a, b| {
        a.last_mod
            .cmp(&b.last_mod)
            .then(a.entry_path().cmp(&b.entry_path()))
    });
    results
}

fn find_recycle_bin_group(groups: &HashMap<String, Group>) -> Option<Group> {
    groups
        .values()
        .find(|group| group.is_recycle_bin)
        .cloned()
        .or_else(|| {
            groups
                .values()
                .find(|group| matches!(group.name.to_lowercase().as_str(), "recycle bin" | "trash"))
                .cloned()
        })
}

fn find_recycle_bin_entries(groups: &HashMap<String, Group>, entries: &[Entry]) -> Vec<Entry> {
    let Some(recycle) = find_recycle_bin_group(groups) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    collect_group_entries(groups, entries, &recycle.path, &mut results);
    results
}

fn find_empty_recycle_bin_groups(groups: &HashMap<String, Group>) -> Vec<Group> {
    let Some(recycle) = find_recycle_bin_group(groups) else {
        return Vec::new();
    };
    let mut results: Vec<Group> = groups
        .values()
        .filter(|group| {
            group.path != recycle.path
                && is_descendant_path(&group.path, &recycle.path)
                && collect_descendant_entry_count(groups, &group.path) == 0
        })
        .cloned()
        .collect();
    results.sort_by(|a, b| {
        b.path
            .matches('/')
            .count()
            .cmp(&a.path.matches('/').count())
            .then(a.path.cmp(&b.path))
    });
    results
}

fn is_descendant_path(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

fn collect_group_entries(
    groups: &HashMap<String, Group>,
    entries: &[Entry],
    path: &str,
    results: &mut Vec<Entry>,
) {
    let Some(group) = groups.get(path) else {
        return;
    };
    for index in &group.direct_entries {
        if let Some(entry) = entries.get(*index) {
            results.push(entry.clone());
        }
    }
    for subgroup in &group.subgroups {
        collect_group_entries(groups, entries, subgroup, results);
    }
}

fn find_old_recycle_entries(
    groups: &HashMap<String, Group>,
    entries: &[Entry],
    days: i64,
) -> Vec<Entry> {
    let cutoff = Utc::now() - TimeDelta::days(days);
    let mut results: Vec<Entry> = find_recycle_bin_entries(groups, entries)
        .into_iter()
        .filter(|entry| entry.last_mod.is_some_and(|last_mod| last_mod < cutoff))
        .collect();
    results.sort_by(|a, b| {
        a.last_mod
            .cmp(&b.last_mod)
            .then(a.entry_path().cmp(&b.entry_path()))
    });
    results
}

fn find_title_case_candidates(entries: &[Entry]) -> Vec<(Entry, String)> {
    let mut results = Vec::new();
    for entry in entries {
        if entry.title.trim().is_empty() {
            continue;
        }
        if looks_like_url_or_domain(&entry.title) {
            continue;
        }
        let new_title = title_to_title_case(&entry.title);
        if new_title != entry.title {
            results.push((entry.clone(), new_title));
        }
    }
    results.sort_by(|a, b| a.0.entry_path().cmp(&b.0.entry_path()));
    results
}

fn find_entries_missing_url(entries: &[Entry]) -> Vec<Entry> {
    let mut results: Vec<Entry> = entries
        .iter()
        .filter(|entry| {
            entry.url.trim().is_empty()
                && (!entry.title.trim().is_empty() || !entry.username.trim().is_empty())
        })
        .cloned()
        .collect();
    results.sort_by_key(|entry| entry.entry_path());
    results
}

fn find_entries_with_passkeys(entries: &[Entry]) -> Vec<Entry> {
    let mut results: Vec<Entry> = entries
        .iter()
        .filter(|entry| has_passkey_metadata(entry))
        .cloned()
        .collect();
    results.sort_by_key(|entry| entry.entry_path());
    results
}

fn find_supported_passkey_candidates(app: &App) -> Vec<(Entry, String, PasskeySite)> {
    let Some(directory) = &app.passkey_directory else {
        return Vec::new();
    };
    let mut results: Vec<(Entry, String, PasskeySite)> = app
        .entries
        .iter()
        .filter(|entry| !has_passkey_metadata(entry))
        .filter_map(|entry| {
            let domain = entry_domain(entry)?;
            let (site_domain, site) = directory.lookup(&domain)?;
            Some((entry.clone(), site_domain, site.clone()))
        })
        .collect();
    results.sort_by_key(|(entry, site_domain, _)| {
        format!(
            "{site_domain}\0{}\0{}",
            entry.username.to_lowercase(),
            entry.entry_path()
        )
    });
    results
}

impl PasskeyDirectory {
    fn lookup(&self, domain: &str) -> Option<(String, &PasskeySite)> {
        for candidate in domain_suffixes(domain) {
            if !self.supported_domains.contains(candidate) {
                continue;
            }
            if let Some(site) = self.sites.get(candidate) {
                return Some((candidate.to_string(), site));
            }
            if let Some((site_domain, site)) = self.sites.iter().find(|(_, site)| {
                site.domain
                    .as_deref()
                    .is_some_and(|domain| domain.eq_ignore_ascii_case(candidate))
                    || site
                        .additional_domains
                        .iter()
                        .any(|domain| domain.eq_ignore_ascii_case(candidate))
            }) {
                return Some((site_domain.clone(), site));
            }
        }
        None
    }
}

fn domain_suffixes(domain: &str) -> Vec<&str> {
    let mut results = Vec::new();
    let mut rest = domain;
    loop {
        results.push(rest);
        let Some((_, suffix)) = rest.split_once('.') else {
            break;
        };
        rest = suffix;
    }
    results
}

fn site_label(site_domain: &str, site: &PasskeySite) -> String {
    site.name
        .as_deref()
        .or(site.domain.as_deref())
        .or(site.url.as_deref())
        .unwrap_or(site_domain)
        .to_string()
}

fn passkey_support_mode(site: &PasskeySite) -> &'static str {
    match (&site.passwordless, &site.mfa) {
        (Some(PasskeySupport::Allowed), _) => "passwordless",
        (_, Some(PasskeySupport::Allowed)) => "mfa",
        _ => "supported",
    }
}

fn passkey_site_detail(site: &PasskeySite) -> String {
    site.documentation
        .as_deref()
        .or(site.url.as_deref())
        .unwrap_or("")
        .to_string()
}

fn has_passkey_metadata(entry: &Entry) -> bool {
    entry.custom_field_keys.iter().any(|key| {
        let normalized = key.to_lowercase();
        normalized.starts_with("kpex_passkey") || normalized.contains("passkey")
    })
}

fn entry_domain(entry: &Entry) -> Option<String> {
    if let Some(domain) = domain_from_value(&entry.url) {
        return Some(domain);
    }
    domain_from_value(&entry.title)
}

fn domain_from_value(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let without_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let host = without_scheme
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_start_matches("www.")
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_lowercase();

    if looks_like_domain(&host) {
        Some(host)
    } else {
        None
    }
}

fn looks_like_domain(value: &str) -> bool {
    let Some((_, suffix)) = value.rsplit_once('.') else {
        return false;
    };
    !value.contains(char::is_whitespace)
        && suffix.len() >= 2
        && suffix.len() <= 24
        && suffix.chars().all(|ch| ch.is_ascii_alphabetic())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.'))
}

fn find_ssh_entries(entries: &[Entry]) -> Vec<Entry> {
    let mut results: Vec<Entry> = entries
        .iter()
        .filter(|entry| is_ssh_entry(entry))
        .cloned()
        .collect();
    results.sort_by_key(|entry| entry.entry_path());
    results
}

fn is_ssh_entry(entry: &Entry) -> bool {
    let searchable = format!(
        "{}\n{}\n{}\n{}\n{}",
        entry.group_path,
        entry.title,
        entry.tags,
        entry.custom_field_keys.join("\n"),
        entry.attachment_names.join("\n")
    )
    .to_lowercase();

    searchable.contains("ssh")
        || searchable.contains(".pub")
        || searchable.contains(".ppk")
        || !entry.public_key_values.is_empty()
        || entry.notes.contains("BEGIN OPENSSH PRIVATE KEY")
        || entry.notes.contains("BEGIN RSA PRIVATE KEY")
        || entry.notes.contains("BEGIN DSA PRIVATE KEY")
        || looks_like_ssh_public_key(&entry.notes)
}

fn ssh_summary(entry: &Entry) -> String {
    if contains_ssh_marker(entry, "ssh-ed25519") {
        "ssh-ed25519".to_string()
    } else if contains_ssh_marker(entry, "ssh-rsa") {
        "ssh-rsa review signature use".to_string()
    } else if contains_ssh_marker(entry, "ssh-dss") || entry.notes.contains("BEGIN DSA PRIVATE KEY")
    {
        "legacy DSA review".to_string()
    } else if contains_ssh_marker(entry, "ecdsa-sha2-") {
        "ecdsa".to_string()
    } else if entry.notes.contains("BEGIN OPENSSH PRIVATE KEY") {
        "private key marker".to_string()
    } else if entry.has_attachment {
        format!("attachment{}", attachment_label(entry))
    } else {
        "ssh-like metadata".to_string()
    }
}

fn attachment_label(entry: &Entry) -> String {
    if entry.attachment_names.is_empty() {
        String::new()
    } else {
        format!(": {}", entry.attachment_names.join(","))
    }
}

fn contains_ssh_marker(entry: &Entry, marker: &str) -> bool {
    entry.notes.contains(marker)
        || entry
            .public_key_values
            .iter()
            .any(|value| value.contains(marker))
        || entry
            .attachment_names
            .iter()
            .any(|name| name.to_lowercase().contains(marker))
}

fn looks_like_ssh_public_key(value: &str) -> bool {
    let value = value.trim_start();
    value.starts_with("ssh-ed25519 ")
        || value.starts_with("ssh-rsa ")
        || value.starts_with("ssh-dss ")
        || value.starts_with("ecdsa-sha2-")
}

fn looks_like_url_or_domain(title: &str) -> bool {
    let value = title.trim();
    if value.contains("://") || value.starts_with("www.") {
        return true;
    }
    looks_like_domain(value)
}

fn title_to_title_case(title: &str) -> String {
    let mut output = String::with_capacity(title.len());
    let mut token = String::new();

    for ch in title.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            token.push(ch);
        } else {
            output.push_str(&convert_title_token(&token));
            token.clear();
            output.push(ch);
        }
    }
    output.push_str(&convert_title_token(&token));
    output
}

fn convert_title_token(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }
    if token.len() <= 5
        && token
            .chars()
            .all(|ch| ch.is_uppercase() || ch.is_ascii_digit())
    {
        return token.to_string();
    }
    let has_upper = token.chars().any(|ch| ch.is_uppercase());
    let has_lower = token.chars().any(|ch| ch.is_lowercase());
    if has_upper && has_lower {
        return token.to_string();
    }
    let mut chars = token.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
}

fn apply_pending(app: &mut App, terminal: &mut TuiTerminal) -> AppResult<()> {
    let Some(action) = app.pending.take() else {
        return Ok(());
    };

    if app.config.read_only {
        set_message(
            app,
            "Read-only Mode",
            "Refusing to apply a vault-modifying action because this session is read-only.",
        );
        return Ok(());
    }

    let title = action.title().to_string();
    let total = action_len(&action);
    let mut changed = 0;
    let mut failed = Vec::new();
    let mut recent = Vec::new();
    let mut cancelled = false;

    set_apply_progress(
        app,
        title.clone(),
        total,
        0,
        changed,
        "Starting",
        "",
        &recent,
    );
    redraw(terminal, app)?;

    match action {
        PendingAction::RemoveEmptyGroups(groups) => {
            for (idx, group) in groups.iter().enumerate() {
                set_apply_progress(
                    app,
                    title.clone(),
                    total,
                    idx + 1,
                    changed,
                    "Removing group",
                    &group.path,
                    &recent,
                );
                redraw(terminal, app)?;
                match cmd_rmdir(app, &group.path) {
                    Ok(()) => {
                        changed += 1;
                        push_recent(&mut recent, format!("removed {}", group.path));
                    }
                    Err(err) => {
                        let failure = format!("{}: {err}", group.path);
                        failed.push(failure.clone());
                        push_recent(&mut recent, format!("failed {failure}"));
                    }
                }
                if should_cancel_apply(app, terminal, &title, total, idx + 1, changed, &recent)? {
                    cancelled = true;
                    push_recent(&mut recent, "cancelled by user".to_string());
                    break;
                }
            }
        }
        PendingAction::PurgeRecycleBinEmptyGroups(groups) => {
            for (idx, group) in groups.iter().enumerate() {
                set_apply_progress(
                    app,
                    title.clone(),
                    total,
                    idx + 1,
                    changed,
                    "Purging empty recycle-bin group",
                    &group.path,
                    &recent,
                );
                redraw(terminal, app)?;
                match cmd_rmdir(app, &group.path) {
                    Ok(()) => {
                        changed += 1;
                        push_recent(&mut recent, format!("purged {}", group.path));
                    }
                    Err(err) => {
                        let failure = format!("{}: {err}", group.path);
                        failed.push(failure.clone());
                        push_recent(&mut recent, format!("failed {failure}"));
                    }
                }
                if should_cancel_apply(app, terminal, &title, total, idx + 1, changed, &recent)? {
                    cancelled = true;
                    push_recent(&mut recent, "cancelled by user".to_string());
                    break;
                }
            }
        }
        PendingAction::ArchiveIdentityDuplicates(entries)
        | PendingAction::ArchiveStale(entries) => {
            set_apply_progress(
                app,
                title.clone(),
                total,
                0,
                changed,
                "Ensuring archive group",
                &app.config.archive_group.clone(),
                &recent,
            );
            redraw(terminal, app)?;
            if let Err(err) = ensure_archive_group(app) {
                let failure = err.to_string();
                failed.push(failure.clone());
                push_recent(&mut recent, format!("failed {failure}"));
            } else {
                if should_cancel_apply(app, terminal, &title, total, 0, changed, &recent)? {
                    cancelled = true;
                    push_recent(&mut recent, "cancelled by user".to_string());
                }
                let archive_group = app.config.archive_group.clone();
                for (idx, entry) in entries.iter().enumerate() {
                    if cancelled {
                        break;
                    }
                    let entry_path = entry.entry_path();
                    set_apply_progress(
                        app,
                        title.clone(),
                        total,
                        idx + 1,
                        changed,
                        "Archiving entry",
                        &entry_path,
                        &recent,
                    );
                    redraw(terminal, app)?;
                    match cmd_mv(app, &entry_path, &archive_group) {
                        Ok(()) => {
                            changed += 1;
                            push_recent(&mut recent, format!("archived {entry_path}"));
                        }
                        Err(err) => {
                            let failure = format!("{entry_path}: {err}");
                            failed.push(failure.clone());
                            push_recent(&mut recent, format!("failed {failure}"));
                        }
                    }
                    if should_cancel_apply(app, terminal, &title, total, idx + 1, changed, &recent)?
                    {
                        cancelled = true;
                        push_recent(&mut recent, "cancelled by user".to_string());
                        break;
                    }
                }
            }
        }
        PendingAction::DeleteIdentityDuplicates(entries)
        | PendingAction::DeleteStale(entries)
        | PendingAction::PurgeRecycleBin(entries) => {
            for (idx, entry) in entries.iter().enumerate() {
                let entry_path = entry.entry_path();
                set_apply_progress(
                    app,
                    title.clone(),
                    total,
                    idx + 1,
                    changed,
                    "Removing entry",
                    &entry_path,
                    &recent,
                );
                redraw(terminal, app)?;
                match cmd_rm(app, &entry_path) {
                    Ok(()) => {
                        changed += 1;
                        push_recent(&mut recent, format!("removed {entry_path}"));
                    }
                    Err(err) => {
                        let failure = format!("{entry_path}: {err}");
                        failed.push(failure.clone());
                        push_recent(&mut recent, format!("failed {failure}"));
                    }
                }
                if should_cancel_apply(app, terminal, &title, total, idx + 1, changed, &recent)? {
                    cancelled = true;
                    push_recent(&mut recent, "cancelled by user".to_string());
                    break;
                }
            }
        }
        PendingAction::ApplyTitleCase(items) => {
            for (idx, (entry, new_title)) in items.iter().enumerate() {
                let entry_path = entry.entry_path();
                let current_item = format!("{entry_path} -> {new_title}");
                set_apply_progress(
                    app,
                    title.clone(),
                    total,
                    idx + 1,
                    changed,
                    "Updating title",
                    &current_item,
                    &recent,
                );
                redraw(terminal, app)?;
                match cmd_edit_title(app, &entry_path, new_title) {
                    Ok(()) => {
                        changed += 1;
                        push_recent(&mut recent, format!("retitled {current_item}"));
                    }
                    Err(err) => {
                        let failure = format!("{entry_path} -> {new_title}: {err}");
                        failed.push(failure.clone());
                        push_recent(&mut recent, format!("failed {failure}"));
                    }
                }
                if should_cancel_apply(app, terminal, &title, total, idx + 1, changed, &recent)? {
                    cancelled = true;
                    push_recent(&mut recent, "cancelled by user".to_string());
                    break;
                }
            }
        }
    }

    set_apply_progress(
        app,
        title,
        total,
        total,
        changed,
        "Reloading database",
        "Refreshing the database model after changes.",
        &recent,
    );
    redraw(terminal, app)?;
    let reload_result = load_database(app);
    let mut body = format!("Changed {changed} items.");
    if cancelled {
        body.push_str("\nCancelled before starting the next item.");
    }
    if !failed.is_empty() {
        body.push_str("\n\nFailures:\n");
        for failure in failed.iter().take(20) {
            body.push_str(failure);
            body.push('\n');
        }
        if failed.len() > 20 {
            body.push_str(&format!("... {} more failures\n", failed.len() - 20));
        }
    }
    if let Err(err) = reload_result {
        body.push_str(&format!("\nReload failed: {err}"));
    }
    app.progress = None;
    set_message(app, "Apply complete", body);
    Ok(())
}

fn action_len(action: &PendingAction) -> usize {
    match action {
        PendingAction::RemoveEmptyGroups(groups)
        | PendingAction::PurgeRecycleBinEmptyGroups(groups) => groups.len(),
        PendingAction::ArchiveIdentityDuplicates(entries)
        | PendingAction::DeleteIdentityDuplicates(entries)
        | PendingAction::ArchiveStale(entries)
        | PendingAction::DeleteStale(entries)
        | PendingAction::PurgeRecycleBin(entries) => entries.len(),
        PendingAction::ApplyTitleCase(items) => items.len(),
    }
}

#[allow(clippy::too_many_arguments)]
fn set_apply_progress(
    app: &mut App,
    title: String,
    total: usize,
    current: usize,
    changed: usize,
    phase: &str,
    current_item: &str,
    recent: &[String],
) {
    app.progress = Some(ApplyProgress {
        title,
        total,
        current,
        changed,
        phase: phase.to_string(),
        current_item: current_item.to_string(),
        recent: recent.to_vec(),
    });
}

fn push_recent(recent: &mut Vec<String>, item: String) {
    recent.push(item);
    if recent.len() > 6 {
        recent.remove(0);
    }
}

fn redraw(terminal: &mut TuiTerminal, app: &App) -> AppResult<()> {
    terminal.draw(|frame| draw(frame, app))?;
    Ok(())
}

fn should_cancel_apply(
    app: &mut App,
    terminal: &mut TuiTerminal,
    title: &str,
    total: usize,
    current: usize,
    changed: usize,
    recent: &[String],
) -> AppResult<bool> {
    if event::poll(Duration::from_millis(1))?
        && let Event::Key(key) = event::read()?
    {
        let cancel = matches!(
            key.code,
            KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Esc
        );
        if cancel {
            set_apply_progress(
                app,
                title.to_string(),
                total,
                current,
                changed,
                "Cancel requested",
                "Stopping before the next item and then reloading the database model.",
                recent,
            );
            redraw(terminal, app)?;
        }
        return Ok(cancel);
    }
    Ok(false)
}

fn ensure_archive_group(app: &App) -> AppResult<()> {
    match run_keepassxc(
        &[
            "mkdir",
            "-q",
            &app.config.database,
            &cli_config_path(app, &app.config.archive_group),
        ],
        Some(&app.password),
    ) {
        Ok(_) => Ok(()),
        Err(AppError::Keepass(msg)) if msg.to_lowercase().contains("exist") => Ok(()),
        Err(err) => Err(err),
    }
}

fn cmd_rmdir(app: &App, group_path: &str) -> AppResult<()> {
    let group_path = cli_model_path(app, group_path);
    run_keepassxc(
        &["rmdir", "-q", &app.config.database, &group_path],
        Some(&app.password),
    )
    .map(|_| ())
}

fn cmd_rm(app: &App, entry_path: &str) -> AppResult<()> {
    let entry_path = cli_model_path(app, entry_path);
    run_keepassxc(
        &["rm", "-q", &app.config.database, &entry_path],
        Some(&app.password),
    )
    .map(|_| ())
}

fn cmd_mv(app: &App, entry_path: &str, dest_group: &str) -> AppResult<()> {
    let entry_path = cli_model_path(app, entry_path);
    let dest_group = cli_config_path(app, dest_group);
    run_keepassxc(
        &["mv", "-q", &app.config.database, &entry_path, &dest_group],
        Some(&app.password),
    )
    .map(|_| ())
}

fn cmd_edit_title(app: &App, entry_path: &str, new_title: &str) -> AppResult<()> {
    let entry_path = cli_model_path(app, entry_path);
    run_keepassxc(
        &[
            "edit",
            "-q",
            "--title",
            new_title,
            &app.config.database,
            &entry_path,
        ],
        Some(&app.password),
    )
    .map(|_| ())
}

fn cli_model_path(app: &App, model_path: &str) -> String {
    let Some(root_path) = root_group_path(app) else {
        return model_path.to_string();
    };
    strip_root_path(model_path, &root_path).to_string()
}

fn cli_config_path(app: &App, path: &str) -> String {
    let Some(root_path) = root_group_path(app) else {
        return path.to_string();
    };
    strip_root_path(path, &root_path).to_string()
}

fn strip_root_path<'a>(path: &'a str, root_path: &str) -> &'a str {
    if path == root_path {
        ""
    } else {
        path.strip_prefix(root_path)
            .and_then(|value| value.strip_prefix('/'))
            .unwrap_or(path)
    }
}

fn root_group_path(app: &App) -> Option<String> {
    app.groups
        .values()
        .find(|group| group.parent_path.is_empty())
        .map(|group| group.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_XML: &str = r#"
<KeePassFile>
  <Meta>
    <RecycleBinUUID>recycle-uuid</RecycleBinUUID>
  </Meta>
  <Root>
    <Group>
      <UUID>root-uuid</UUID>
      <Name>Database</Name>
      <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
      <Entry>
        <UUID>entry-a</UUID>
        <Times><LastModificationTime>2020-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>github</Value></String>
        <String><Key>UserName</Key><Value>me</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
      </Entry>
      <Entry>
        <UUID>entry-b</UUID>
        <Times><LastModificationTime>2022-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>github old</Value></String>
        <String><Key>UserName</Key><Value>me</Value></String>
        <String><Key>URL</Key><Value>https://github.com</Value></String>
      </Entry>
      <Entry>
        <UUID>entry-c</UUID>
        <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>no url account</Value></String>
        <String><Key>UserName</Key><Value>me</Value></String>
      </Entry>
      <Entry>
        <UUID>entry-passkey</UUID>
        <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>Example</Value></String>
        <String><Key>UserName</Key><Value>me</Value></String>
        <String><Key>URL</Key><Value>https://example.com/login</Value></String>
        <String><Key>KPEX_PASSKEY_RP_ID</Key><Value>example.com</Value></String>
      </Entry>
      <Entry>
        <UUID>entry-ssh</UUID>
        <Times><LastModificationTime>2024-01-01T00:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>github ssh key</Value></String>
        <String><Key>UserName</Key><Value>git</Value></String>
        <String><Key>Public Key</Key><Value>ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKey comment</Value></String>
      </Entry>
      <Group>
        <UUID>empty-uuid</UUID>
        <Name>Empty</Name>
      </Group>
      <Group>
        <UUID>recycle-uuid</UUID>
        <Name>Recycle Bin</Name>
        <Group>
          <UUID>recycled-empty-uuid</UUID>
          <Name>Deleted Empty Group</Name>
        </Group>
        <Entry>
          <UUID>trashed</UUID>
          <Times><LastModificationTime>2020-01-01T00:00:00Z</LastModificationTime></Times>
          <String><Key>Title</Key><Value>old trash</Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>
"#;

    #[test]
    fn builds_model_and_finds_audits() {
        let (groups, entries) = build_model(SAMPLE_XML).expect("sample XML should parse");

        assert_eq!(entries.len(), 6);
        assert!(groups.contains_key("Database/Empty"));
        assert_eq!(find_empty_groups(&groups).len(), 1);
        assert_eq!(find_duplicates_by_identity(&entries).len(), 1);
        assert_eq!(duplicate_identity_action_entries(&entries).len(), 1);
        assert_eq!(find_entries_missing_url(&entries).len(), 3);
        assert_eq!(
            find_title_case_candidates(&entries)
                .iter()
                .find(|(entry, _)| entry.title == "github old")
                .map(|(_, new_title)| new_title.as_str()),
            Some("Github Old")
        );
        assert_eq!(find_recycle_bin_entries(&groups, &entries).len(), 1);
        assert_eq!(find_empty_recycle_bin_groups(&groups).len(), 1);
    }

    #[test]
    fn title_case_preserves_short_acronyms_and_mixed_case() {
        assert_eq!(title_to_title_case("NASA login"), "NASA Login");
        assert_eq!(title_to_title_case("eBay backup"), "eBay Backup");
        assert_eq!(title_to_title_case("github-api"), "Github-Api");
    }

    #[test]
    fn title_case_skips_domain_like_titles() {
        let entry = Entry {
            group_path: "Database/Bitwarden Import".to_string(),
            title: "80000hours.org".to_string(),
            username: String::new(),
            url: String::new(),
            notes: String::new(),
            uuid: "domain-title".to_string(),
            last_mod: None,
            tags: String::new(),
            has_attachment: false,
            attachment_names: Vec::new(),
            custom_field_keys: Vec::new(),
            public_key_values: Vec::new(),
        };

        assert!(looks_like_url_or_domain(&entry.title));
        assert!(find_title_case_candidates(&[entry]).is_empty());
    }

    #[test]
    fn duplicate_identity_action_keeps_newest_entry() {
        let (_, entries) = build_model(SAMPLE_XML).expect("sample XML should parse");
        let action_entries = duplicate_identity_action_entries(&entries);

        assert_eq!(action_entries.len(), 1);
        assert_eq!(action_entries[0].uuid, "entry-a");
    }

    #[test]
    fn passkey_and_ssh_reports_detect_metadata_without_passwords() {
        let (_, entries) = build_model(SAMPLE_XML).expect("sample XML should parse");

        assert_eq!(find_entries_with_passkeys(&entries).len(), 1);
        assert_eq!(
            entry_domain(
                entries
                    .iter()
                    .find(|entry| entry.uuid == "entry-passkey")
                    .expect("passkey entry exists")
            )
            .as_deref(),
            Some("example.com")
        );
        assert_eq!(find_ssh_entries(&entries).len(), 1);
        assert_eq!(
            ssh_summary(
                entries
                    .iter()
                    .find(|entry| entry.uuid == "entry-ssh")
                    .expect("ssh entry exists")
            ),
            "ssh-ed25519"
        );
    }

    #[test]
    fn passkey_directory_matches_supported_domains_only() {
        let (_, entries) = build_model(SAMPLE_XML).expect("sample XML should parse");
        let mut sites = HashMap::new();
        sites.insert(
            "github.com".to_string(),
            PasskeySite {
                name: Some("GitHub".to_string()),
                domain: None,
                url: None,
                documentation: Some("https://github.com/settings/security".to_string()),
                passwordless: Some(PasskeySupport::Unsupported),
                mfa: Some(PasskeySupport::Allowed),
                additional_domains: Vec::new(),
            },
        );
        let mut supported_domains = HashSet::new();
        supported_domains.insert("github.com".to_string());

        let app = App {
            config: AppConfig {
                database: "synthetic.kdbx".to_string(),
                stale_years: 3,
                recycle_days: 30,
                archive_group: DEFAULT_ARCHIVE_GROUP.to_string(),
                preview_rows: 50,
                passkey_directory: None,
                read_only: false,
                report_path: None,
            },
            password: String::new(),
            groups: HashMap::new(),
            entries,
            passkey_directory: Some(PasskeyDirectory {
                sites,
                supported_domains,
            }),
            screen: Screen::Overview,
            selected: 0,
            focus: Focus::Audits,
            pending: None,
            message: None,
            progress: None,
            should_quit: false,
        };

        let candidates = find_supported_passkey_candidates(&app);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|(_, domain, _)| domain == "github.com")
        );
    }

    #[test]
    fn passkey_directory_accepts_allowed_string_values() {
        let json = r#"{
          "adobe.com": {
            "passwordless": "allowed",
            "documentation": "https://helpx.adobe.com/manage-account/using/secure-sign-in-with-passkey.html"
          },
          "example.com": {
            "mfa": false
          }
        }"#;

        let sites: HashMap<String, PasskeySite> =
            serde_json::from_str(json).expect("directory JSON should parse");
        assert_eq!(
            sites
                .get("adobe.com")
                .and_then(|site| site.passwordless.as_ref()),
            Some(&PasskeySupport::Allowed)
        );
        assert_eq!(
            sites.get("example.com").and_then(|site| site.mfa.as_ref()),
            Some(&PasskeySupport::Unsupported)
        );
    }

    #[test]
    fn cli_paths_strip_export_root_group() {
        assert_eq!(
            strip_root_path("Database/Shopping/Amazon", "Database"),
            "Shopping/Amazon"
        );
        assert_eq!(
            strip_root_path("Shopping/Amazon", "Database"),
            "Shopping/Amazon"
        );
    }
}
