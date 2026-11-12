use crate::{Client, ClientError, PollReport, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use signal_storage::{Contact, Direction, MessageContent};
use std::collections::VecDeque;
use std::io::{stdout, Write};
use std::time::{Duration, Instant};
use uuid::Uuid;

const HELP: &str = "/add USER · /open USER · /session USER · /send TEXT · /media PATH MIME · /read · /fingerprint · /verify HEX · /rotate · /retry · /poll · /quit";

pub fn read_passphrase(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    enable_raw_mode()?;
    let raw = RawModeGuard;
    let result = read_passphrase_inner();
    drop(raw);
    eprintln!();
    result
}

fn read_passphrase_inner() -> Result<String> {
    let mut passphrase = String::new();
    loop {
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match key.code {
            KeyCode::Enter => return Ok(passphrase),
            KeyCode::Backspace => {
                passphrase.pop();
            }
            KeyCode::Esc => {
                return Err(ClientError::InvalidInput(
                    "passphrase entry cancelled".to_owned(),
                ));
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Err(ClientError::InvalidInput(
                    "passphrase entry cancelled".to_owned(),
                ));
            }
            KeyCode::Char(character)
                if !character.is_control()
                    && passphrase.len().saturating_add(character.len_utf8()) <= 1024 =>
            {
                passphrase.push(character);
            }
            _ => {}
        }
    }
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn new() -> Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(stdout(), EnterAlternateScreen) {
            disable_raw_mode()?;
            return Err(error.into());
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(stdout(), LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

pub async fn run(client: Client) -> Result<()> {
    let _guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;
    let result = App::new(client)?.event_loop(&mut terminal).await;
    drop(terminal);
    result
}

struct App {
    client: Client,
    contacts: Vec<Contact>,
    selected: usize,
    input: String,
    log: VecDeque<String>,
    last_poll: Instant,
}

impl App {
    fn new(client: Client) -> Result<Self> {
        let contacts = client.contacts()?;
        let mut app = Self {
            client,
            contacts,
            selected: 0,
            input: String::new(),
            log: VecDeque::new(),
            last_poll: Instant::now(),
        };
        app.sort_contacts();
        app.log(format!(
            "Registered as {}. Type /help for commands.",
            app.client.username()
        ));
        Ok(app)
    }

    async fn event_loop(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    ) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            if event::poll(Duration::from_millis(150))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    if key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        return Ok(());
                    }
                    match key.code {
                        KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                        KeyCode::Down if !self.contacts.is_empty() => {
                            self.selected = (self.selected + 1).min(self.contacts.len() - 1);
                        }
                        KeyCode::Backspace => {
                            self.input.pop();
                        }
                        KeyCode::Esc => self.input.clear(),
                        KeyCode::Enter => {
                            let command = std::mem::take(&mut self.input);
                            let keep_running = match self.execute(&command).await {
                                Ok(keep_running) => keep_running,
                                Err(error) => {
                                    self.log(format!("Error: {error}"));
                                    true
                                }
                            };
                            if !keep_running {
                                return Ok(());
                            }
                        }
                        KeyCode::Char(character)
                            if !character.is_control()
                                && self.input.len().saturating_add(character.len_utf8())
                                    <= 4096 =>
                        {
                            self.input.push(character);
                        }
                        _ => {}
                    }
                }
            }
            if self.last_poll.elapsed() >= Duration::from_secs(5) {
                match self.client.poll().await {
                    Ok(report) => self.show_report(report),
                    Err(error) => self.log(format!("Polling failed: {error}")),
                }
                self.last_poll = Instant::now();
            }
        }
    }

    fn draw(&self, frame: &mut Frame<'_>) {
        let vertical = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .split(frame.area());
        let title = format!(
            " Signal Rust · {} · end-to-end encrypted ",
            self.client.username()
        );
        frame.render_widget(
            Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
            vertical[0],
        );
        let body = Layout::horizontal([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(vertical[1]);
        let contacts = if self.contacts.is_empty() {
            "No contacts. Use /add USER.".to_owned()
        } else {
            self.contacts
                .iter()
                .enumerate()
                .map(|(index, contact)| {
                    format!(
                        "{} {} [{}]",
                        if index == self.selected { ">" } else { " " },
                        contact.username,
                        if contact.verified { "verified" } else { "TOFU" }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        frame.render_widget(
            Paragraph::new(contacts)
                .block(Block::default().title(" Contacts ").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            body[0],
        );
        frame.render_widget(
            Paragraph::new(self.history_text())
                .style(Style::default().fg(Color::White))
                .block(
                    Block::default()
                        .title(" Conversation ")
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false }),
            body[1],
        );
        let log_height = vertical[2].height.saturating_sub(2) as usize;
        let logs = self
            .log
            .iter()
            .skip(self.log.len().saturating_sub(log_height))
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        frame.render_widget(
            Paragraph::new(logs)
                .block(Block::default().title(" Events ").borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            vertical[2],
        );
        frame.render_widget(
            Paragraph::new(self.input.clone()).block(
                Block::default()
                    .title(" Command (↑/↓ selects a contact) ")
                    .borders(Borders::ALL),
            ),
            vertical[3],
        );
    }

    fn history_text(&self) -> String {
        let Some(contact) = self.contacts.get(self.selected) else {
            return "Select a contact to view encrypted local history.".to_owned();
        };
        let Ok(messages) = self.client.history(contact.user_id) else {
            return "History could not be decrypted.".to_owned();
        };
        if messages.is_empty() {
            return "No messages. /send TEXT starts a session automatically.".to_owned();
        }
        messages
            .iter()
            .skip(messages.len().saturating_sub(50))
            .map(|message| {
                let direction = if message.direction == Direction::Outgoing {
                    "you"
                } else {
                    contact.username.as_str()
                };
                let content = match &message.content {
                    MessageContent::Text { text } => safe(text),
                    MessageContent::Media(media) => format!(
                        "[media {} · {} · {} bytes · sha256 {}]",
                        safe(&media.filename),
                        safe(&media.mime_type),
                        media.size,
                        hex_digest(&media.sha256)
                    ),
                    MessageContent::DeliveryReceipt { message_id } => {
                        format!("[delivery receipt {message_id}]")
                    }
                    MessageContent::ReadReceipt { message_ids } => {
                        format!("[read receipt for {} messages]", message_ids.len())
                    }
                };
                format!(
                    "{direction} [{}]: {content}",
                    format!("{:?}", message.state).to_lowercase()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    async fn execute(&mut self, command: &str) -> Result<bool> {
        let command = command.trim();
        if command.is_empty() {
            return Ok(true);
        }
        if command == "/quit" || command == "/exit" {
            return Ok(false);
        }
        if command == "/help" {
            self.log(HELP);
            return Ok(true);
        }
        if !command.starts_with('/') {
            let text = command.to_owned();
            return self.send_text(&text).await;
        }
        let (operation, arguments) = command
            .split_once(char::is_whitespace)
            .map_or((command, ""), |(operation, arguments)| {
                (operation, arguments.trim())
            });
        match operation {
            "/add" => {
                let contact = self.client.add_contact(arguments).await?;
                self.log(format!(
                    "Pinned {}. Compare the fingerprint out of band before /verify.",
                    contact.username
                ));
                self.select(contact.user_id);
            }
            "/open" => {
                let contact = self.client.contact(arguments)?;
                self.select(contact.user_id);
            }
            "/session" => {
                let contact = self.client.start_session(arguments).await?;
                self.log(format!("Session ready for {}.", contact.username));
                self.select(contact.user_id);
            }
            "/send" => return self.send_text(arguments).await,
            "/media" => {
                let (path, mime_type) = arguments.split_once(' ').ok_or_else(|| {
                    ClientError::InvalidInput("usage: /media PATH MIME".to_owned())
                })?;
                let username = self.selected_contact()?.username;
                let id = self.client.send_media(&username, path, mime_type).await?;
                self.log(format!("Encrypted media metadata queued: {id}"));
            }
            "/poll" => {
                let report = self.client.poll().await?;
                self.show_report(report);
            }
            "/retry" => {
                let count = self.client.flush_outbox().await?;
                self.log(format!("Relay accepted {count} outbox packet(s)."));
            }
            "/read" => {
                let username = self.selected_contact()?.username;
                match self.client.send_read_receipt(&username).await? {
                    Some(id) => self.log(format!("Read receipt queued: {id}")),
                    None => self.log("No unread incoming messages."),
                }
            }
            "/fingerprint" => {
                let contact = self.selected_contact()?;
                self.log(format!("{}: {}", contact.username, contact.fingerprint));
            }
            "/verify" => {
                let contact = self.selected_contact()?;
                if arguments.len() != 64 || !arguments.eq_ignore_ascii_case(&contact.fingerprint) {
                    return Err(ClientError::InvalidInput(
                        "fingerprint does not match; verification unchanged".to_owned(),
                    ));
                }
                self.client.verify_contact(contact.user_id)?;
                self.log(format!("Verified {}.", contact.username));
                self.select(contact.user_id);
            }
            "/rotate" => {
                self.client.rotate_prekeys().await?;
                self.log("Uploaded a fresh signed pre-key and 20 one-time pre-keys.");
            }
            _ => {
                return Err(ClientError::InvalidInput(format!(
                    "unknown command {operation}; type /help"
                )));
            }
        }
        Ok(true)
    }

    async fn send_text(&mut self, text: &str) -> Result<bool> {
        let username = self.selected_contact()?.username;
        let id = self.client.send_text(&username, text).await?;
        self.log(format!("Message accepted by relay: {id}"));
        Ok(true)
    }

    fn selected_contact(&self) -> Result<Contact> {
        self.contacts
            .get(self.selected)
            .cloned()
            .ok_or(ClientError::UnknownContact)
    }

    fn select(&mut self, user_id: Uuid) {
        self.sort_contacts();
        if let Some(index) = self
            .contacts
            .iter()
            .position(|contact| contact.user_id == user_id)
        {
            self.selected = index;
        }
    }

    fn sort_contacts(&mut self) {
        if let Ok(contacts) = self.client.contacts() {
            self.contacts = contacts;
        }
        self.contacts
            .sort_by(|left, right| left.username.cmp(&right.username));
        if self.contacts.is_empty() {
            self.selected = 0;
        } else {
            self.selected = self.selected.min(self.contacts.len() - 1);
        }
    }

    fn show_report(&mut self, report: PollReport) {
        for event in report.events {
            if let Ok(contact) = self.client.contact(&self.contact_name(event.peer_id)) {
                self.log(format!("New encrypted event from {}.", contact.username));
            }
        }
        for warning in report.warnings {
            self.log(format!("Warning: {warning}"));
        }
        self.sort_contacts();
    }

    fn contact_name(&self, user_id: Uuid) -> String {
        self.contacts
            .iter()
            .find(|contact| contact.user_id == user_id)
            .map(|contact| contact.username.clone())
            .unwrap_or_default()
    }

    fn log(&mut self, message: impl AsRef<str>) {
        const MAX_LOG: usize = 200;
        let message: String = safe(message.as_ref()).chars().take(500).collect();
        self.log.push_back(message);
        while self.log.len() > MAX_LOG {
            self.log.pop_front();
        }
    }
}

fn safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() && character != '\n' {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
