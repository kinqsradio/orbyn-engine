//! What each email says, as designed (Orbyn Account Designs, the Emails group).
//!
//! Every message is sent as HTML and plain text together, and every string here is copied from
//! those designs: the subject says the one purpose, the first line repeats it, and the only button
//! does it. The HTML is one column 560px wide in system fonts, with no images, no tracking and no
//! background colour (only text colour on the client's own background, plus one filled button),
//! so it reads in dark mode. Times are in UTC and say so. A link carries its token after `#`.
//!
//! A message's one value, [`super::Mail::code`], is the verification code for a code email, and
//! `<time as RFC 3339>\n<link or empty>` for the other two: the attempt time and the sign-in link,
//! or the deletion time and the cancel link. For the unused-account email it is the link alone,
//! empty when there is none. It travels only in the sealed queue entry.

use chrono::{DateTime, Utc};

use super::{Kind, Mail};

/// A message ready to send: the subject, and the same message as plain text and as HTML. It holds
/// a code or a cancel token, so `Debug` shows none of it, only sizes.
#[derive(Clone, PartialEq, Eq)]
pub struct Rendered {
    pub subject: String,
    pub text: String,
    pub html: String,
}

impl std::fmt::Debug for Rendered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rendered")
            .field("subject", &format_args!("({} bytes)", self.subject.len()))
            .field("text", &format_args!("({} bytes)", self.text.len()))
            .field("html", &format_args!("({} bytes)", self.html.len()))
            .finish()
    }
}

const FOOTER_HTML: &str = "Sent by Orbyn because of an action on your account. You can reply to this email. Orbyn never asks for your password or codes by email.";
const FOOTER_TEXT: &str = "--\nSent by Orbyn because of an action on your account.\nYou can reply to this email. Orbyn never asks for your\npassword or codes by email.";

pub(super) fn render(mail: &Mail) -> Option<Rendered> {
    let value = mail.code.as_deref()?;
    match mail.kind {
        Kind::VerifyEmail => Some(code_email(value)),
        Kind::SignUpAttempt => {
            let (at, link) = time_and_link(value)?;
            Some(exists_email(&mail.to, at, link))
        }
        Kind::DeletionScheduled => {
            let (at, link) = time_and_link(value)?;
            Some(delete_email(&mail.to, at, link))
        }
        // The value is the link, or empty when the server has no account site.
        Kind::DeleteUnused => Some(delete_unused_email(&mail.to, http_link(value))),
    }
}

/// The time and the link of a value: RFC 3339, a newline, and the link (empty when there is none;
/// anything that is not an `http(s)` address, such as a bare token, counts as none).
fn time_and_link(value: &str) -> Option<(DateTime<Utc>, Option<&str>)> {
    let (when, link) = value.split_once('\n').unwrap_or((value, ""));
    let at = DateTime::parse_from_rfc3339(when).ok()?.with_timezone(&Utc);
    let link = (link.starts_with("https://") || link.starts_with("http://")).then_some(link);
    Some((at, link))
}

/// A value that is an `http(s)` address; anything else counts as no link.
fn http_link(value: &str) -> Option<&str> {
    (value.starts_with("https://") || value.starts_with("http://")).then_some(value)
}

/// "Saturday 14 November 2026 at 12:00 UTC".
fn long_time(at: DateTime<Utc>) -> String {
    at.format("%A %-d %B %Y at %H:%M UTC").to_string()
}

/// "14 November".
fn short_date(at: DateTime<Utc>) -> String {
    at.format("%-d %B").to_string()
}

/// "482 913" for a six-digit code; any other code as it is.
fn spaced(code: &str) -> String {
    if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_owned()
    }
}

/// The host of a link, for "check your devices at <host>".
fn host_of(link: &str) -> Option<String> {
    url::Url::parse(link).ok()?.host_str().map(str::to_owned)
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

// ---- the three emails ----

fn code_email(code: &str) -> Rendered {
    let subject = format!("Your Orbyn code is {code}");
    let text = format!(
        "Your Orbyn code is {code}\n\n\
         Use this code to finish creating your Orbyn account:\n\n    {code}\n\n\
         It works for 30 minutes.\n\n\
         Didn't try to create an Orbyn account? You can ignore\n\
         this email. No account is created without the code.\n\n{FOOTER_TEXT}\n"
    );
    let mut html = Html::new(&subject);
    html.heading("Your code");
    html.paragraph("Use this code to finish creating your Orbyn account.");
    html.code(&spaced(code));
    html.paragraph("It works for 30 minutes.");
    html.quiet("Didn’t try to create an Orbyn account? You can ignore this email. No account is created without the code.");
    Rendered {
        subject,
        text,
        html: html.finish(),
    }
}

fn exists_email(to: &str, at: DateTime<Utc>, link: Option<&str>) -> Rendered {
    let subject = "Someone tried to create an Orbyn account with your email".to_owned();
    let when = long_time(at);
    // With no account URL there is no link: the email says to open the app, with no button.
    let sign_in = match link {
        Some(link) => format!("If this was you, sign in instead:\n{link}\n\n"),
        None => format!(
            "If this was you, open Orbyn and sign in with\n{to} instead of creating a new account.\n\n"
        ),
    };
    let text = format!(
        "Someone tried to create an Orbyn account with your email\n\n\
         Someone tried to create a new Orbyn account with\n{to} on {when}.\n\n\
         {sign_in}If it wasn't, you don't need to do anything. Nothing on\n\
         your account changed, and no one can get in with your\n\
         email address alone.\n\n{FOOTER_TEXT}\n"
    );
    let mut html = Html::new(&subject);
    html.heading("You already have an Orbyn account");
    html.raw_paragraph(&format!(
        "Someone tried to create a new Orbyn account with {} on {when}.",
        escape(to)
    ));
    match link {
        Some(link) => {
            html.raw_paragraph("<b>If this was you,</b> sign in instead.");
            html.button(link, "Sign in to Orbyn");
        }
        None => html.raw_paragraph(&format!(
            "<b>If this was you,</b> open Orbyn and sign in with {} instead of creating a new account.",
            escape(to)
        )),
    }
    html.quiet_raw("<b>If it wasn’t,</b> you don’t need to do anything. Nothing on your account changed, and no one can get in with your email address alone.");
    Rendered {
        subject,
        text,
        html: html.finish(),
    }
}

fn delete_email(to: &str, at: DateTime<Utc>, link: Option<&str>) -> Rendered {
    let subject = format!("Your Orbyn account will be deleted on {}", short_date(at));
    let when = long_time(at);
    let host = link.and_then(host_of);
    // The plain-text line breaks are the design's: the host starts its own line.
    let (check_text, check_html) = match &host {
        Some(host) => (
            format!("check your devices at\n{host}"),
            format!("check your devices at {host}"),
        ),
        None => (
            "check your devices in\nSettings > Account > Devices".to_owned(),
            "check your devices in Settings › Account › Devices".to_owned(),
        ),
    };
    let cancel_text = match link {
        Some(link) => format!(
            "Changed your mind? Cancel deletion:\n{link}\n\n\
             This link works once and doesn't need you to sign in. You\n\
             can also cancel from any device where you're signed in:\n\
             Settings > Account > Cancel deletion.\n\n"
        ),
        None => "Changed your mind? Open Orbyn on any device where you're\n\
                 signed in and go to Settings > Account > Cancel deletion.\n\
                 You have until the date above.\n\n"
            .to_owned(),
    };
    let text = format!(
        "{subject}\n\n\
         You asked to delete your Orbyn account, {to}.\n\
         It will be deleted on {when},\n\
         with everything in it in every Orbyn app. Until then,\n\
         everything keeps working.\n\n\
         {cancel_text}\
         If you asked for this, there's nothing else to do. If you\n\
         didn't, cancel now and then {check_text}.\n\n{FOOTER_TEXT}\n"
    );
    let mut html = Html::new(&subject);
    html.heading("Your account will be deleted");
    html.raw_paragraph(&format!(
        "You asked to delete your Orbyn account, {}. It will be deleted on <b>{when}</b>, with everything in it in every Orbyn app. Until then, everything keeps working.",
        escape(to)
    ));
    if let Some(link) = link {
        html.raw_paragraph("<b>Changed your mind?</b>");
        html.button(link, "Cancel deletion");
        html.quiet("The button works once and doesn’t need you to sign in. You can also cancel from any device where you’re signed in: Settings › Account › Cancel deletion.");
    } else {
        html.raw_paragraph("<b>Changed your mind?</b> Open Orbyn on any device where you’re signed in and go to Settings › Account › Cancel deletion. You have until the date above.");
    }
    html.quiet(&format!(
        "If you asked for this, there’s nothing else to do. If you didn’t, cancel now and then {}.",
        escape(&check_html)
    ));
    Rendered {
        subject,
        text,
        html: html.finish(),
    }
}

/// The link that deletes an unused account (Account Designs v33, `so-email` and `so-email-local`).
/// How long the link lasts is [`crate::accounts::DELETE_UNUSED_TTL`], said in words.
fn delete_unused_email(to: &str, link: Option<&str>) -> Rendered {
    let subject = "Delete your unused Orbyn account".to_owned();
    let lasts = super::lifetime_words(crate::accounts::DELETE_UNUSED_TTL.as_secs());
    let (text, mut html) = match link {
        Some(link) => {
            let text = format!(
                "Delete your unused Orbyn account\n\n\
                 You asked to delete the Orbyn account {to} so\n\
                 you can sign up again. It has nothing stored in it.\n\n\
                 Delete this account:\n{link}\n\n\
                 This link works once and expires in {lasts}. It doesn't need\n\
                 you to sign in. It only deletes an account with nothing\n\
                 stored in it. If the account has anything in it, nothing\n\
                 is deleted.\n\n\
                 If you didn't ask for this, ignore this email. Nothing\n\
                 happens unless the link is opened and the button pressed.\n\n{FOOTER_TEXT}\n"
            );
            let mut html = Html::new(&subject);
            html.heading("Delete your empty Orbyn account");
            html.raw_paragraph(&format!(
                "You asked to delete the Orbyn account {} so you can sign up again. It has nothing stored in it.",
                escape(to)
            ));
            html.danger_button(link, "Delete this account");
            html.quiet(&format!(
                "The button works once and expires in {lasts}. It doesn’t need you to sign in. It only deletes an account with nothing stored in it. If the account has anything in it, nothing is deleted."
            ));
            (text, html)
        }
        None => {
            let text = format!(
                "Your empty Orbyn account\n\n\
                 You asked to delete the Orbyn account {to} so\n\
                 you can sign up again. It has nothing stored in it.\n\n\
                 This server has no account site, so there's no link. Ask\n\
                 whoever runs this server to delete the empty account\n\
                 {to}. Then sign up again.\n\n\
                 If you didn't ask for this, you can ignore this email.\n\n{FOOTER_TEXT}\n"
            );
            let mut html = Html::new(&subject);
            html.heading("Your empty Orbyn account");
            html.raw_paragraph(&format!(
                "You asked to delete the Orbyn account {} so you can sign up again. It has nothing stored in it.",
                escape(to)
            ));
            html.raw_paragraph(&format!(
                "This server has no account site, so there’s no link. Ask whoever runs this server to delete the empty account {}. Then sign up again.",
                escape(to)
            ));
            (text, html)
        }
    };
    html.quiet(if link.is_some() {
        "If you didn’t ask for this, ignore this email. Nothing happens unless the button is pressed."
    } else {
        "If you didn’t ask for this, you can ignore this email."
    });
    Rendered {
        subject,
        text,
        html: html.finish(),
    }
}

// ---- the HTML ----

/// A small builder for the one-column layout.
struct Html {
    body: String,
    title: String,
}

const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO: &str = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";

impl Html {
    fn new(subject: &str) -> Self {
        let mut html = Self {
            body: String::new(),
            title: escape(subject),
        };
        html.body
            .push_str("<p style=\"margin:0 0 12px;font-weight:500\">Orbyn</p>\n");
        html
    }

    fn heading(&mut self, text: &str) {
        self.body.push_str(&format!(
            "<h1 style=\"margin:0 0 12px;font-size:20px;font-weight:500;line-height:1.3\">{}</h1>\n",
            escape(text)
        ));
    }

    fn paragraph(&mut self, text: &str) {
        self.raw_paragraph(&escape(text));
    }

    fn raw_paragraph(&mut self, html: &str) {
        self.body
            .push_str(&format!("<p style=\"margin:0 0 12px\">{html}</p>\n"));
    }

    /// A less prominent paragraph: the same text colour, a little smaller and lighter.
    fn quiet(&mut self, text: &str) {
        self.quiet_raw(&escape(text));
    }

    fn quiet_raw(&mut self, html: &str) {
        self.body.push_str(&format!(
            "<p style=\"margin:0 0 12px;font-size:13px;opacity:.75\">{html}</p>\n"
        ));
    }

    fn code(&mut self, spaced: &str) {
        self.body.push_str(&format!(
            "<p style=\"margin:4px 0 16px;font-family:{MONO};font-size:30px;letter-spacing:.18em\">{}</p>\n",
            escape(spaced)
        ));
    }

    /// The same button in the design's danger colour, for an action that deletes: the light-theme
    /// danger fill `#d42a2a` with white text. It has no class, so the dark-mode rule that flips
    /// the ordinary button leaves it red.
    fn danger_button(&mut self, link: &str, label: &str) {
        self.body.push_str(&format!(
            "<p style=\"margin:4px 0 16px\"><a href=\"{}\" style=\"display:inline-block;padding:11px 18px;border-radius:10px;background:#d42a2a;color:#ffffff;font-weight:500;text-decoration:none\">{}</a></p>\n",
            escape(link),
            escape(label)
        ));
    }

    /// The one filled button. Its link is the only address in the message.
    fn button(&mut self, link: &str, label: &str) {
        self.body.push_str(&format!(
            "<p style=\"margin:4px 0 16px\"><a class=\"btn\" href=\"{}\" style=\"display:inline-block;padding:11px 18px;border-radius:10px;background:#111111;color:#ffffff;font-weight:500;text-decoration:none\">{}</a></p>\n",
            escape(link),
            escape(label)
        ));
    }

    fn finish(self) -> String {
        format!(
            "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
             <meta name=\"color-scheme\" content=\"light dark\">\n\
             <meta name=\"supported-color-schemes\" content=\"light dark\">\n\
             <title>{}</title>\n\
             <style>@media (prefers-color-scheme:dark){{a.btn{{background:#ffffff!important;color:#111111!important}}}}</style>\n\
             </head>\n<body style=\"margin:0;padding:0\">\n\
             <div style=\"max-width:560px;margin:0 auto;padding:24px 28px;font-family:{FONT};font-size:14px;line-height:1.6\">\n\
             {}<p style=\"margin:20px 0 0;padding-top:12px;border-top:1px solid currentColor;font-size:12px;opacity:.6\">{FOOTER_HTML}</p>\n\
             </div>\n</body>\n</html>\n",
            self.title, self.body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOOTER_LINES: &str = "--\nSent by Orbyn because of an action on your account.\nYou can reply to this email. Orbyn never asks for your\npassword or codes by email.\n";

    fn mail(kind: Kind, code: Option<&str>) -> Mail {
        Mail {
            kind,
            account: None,
            to: "sam@example.com".to_owned(),
            code: code.map(str::to_owned),
        }
    }

    fn rendered(kind: Kind, value: &str) -> Rendered {
        mail(kind, Some(value)).render().expect("renders")
    }

    /// Every address in an HTML part (anything with `://`, any `src`, any CSS `url(`), so a test
    /// can say the action link is the only one.
    fn remote_things(html: &str) -> Vec<String> {
        let mut found = Vec::new();
        for (i, _) in html.match_indices("://") {
            let start = html[..i]
                .rfind(|c: char| c == '"' || c == '\'' || c.is_whitespace())
                .map_or(0, |s| s + 1);
            let end = html[i..]
                .find(['"', '\'', '<', ' '])
                .map_or(html.len(), |e| i + e);
            found.push(html[start..end].to_owned());
        }
        for needle in [
            "<img",
            " src=",
            "url(",
            "@import",
            "<link",
            "<script",
            "<iframe",
            "background-image",
        ] {
            assert!(!html.contains(needle), "{needle} in the HTML part");
        }
        found
    }

    fn common(html: &str) {
        assert!(html.contains("<p style=\"margin:0 0 12px;font-weight:500\">Orbyn</p>"));
        assert!(html.contains("max-width:560px"));
        assert!(html.contains("font-family:-apple-system"));
        // Text colour on the client's background: no background on the page, one filled button.
        assert!(html.matches("background:#111111").count() <= 1);
        assert!(!html.contains("background-color"));
        assert!(html.contains("Sent by Orbyn because of an action on your account. You can reply to this email. Orbyn never asks for your password or codes by email."));
    }

    #[test]
    fn the_code_email_is_as_designed() {
        let r = rendered(Kind::VerifyEmail, "482913");
        assert_eq!(r.subject, "Your Orbyn code is 482913");
        assert_eq!(
            r.text,
            format!(
                "Your Orbyn code is 482913\n\n\
                 Use this code to finish creating your Orbyn account:\n\n    482913\n\n\
                 It works for 30 minutes.\n\n\
                 Didn't try to create an Orbyn account? You can ignore\n\
                 this email. No account is created without the code.\n\n{FOOTER_LINES}"
            )
        );
        common(&r.html);
        assert!(r.html.contains(">Your code</h1>"));
        assert!(
            r.html
                .contains("Use this code to finish creating your Orbyn account.")
        );
        assert!(r.html.contains(">482 913</p>"), "spaced in the body");
        assert!(r.html.contains("It works for 30 minutes."));
        assert!(r.html.contains("Didn’t try to create an Orbyn account? You can ignore this email. No account is created without the code."));
        assert!(!r.html.contains("<a "), "no button on a code email");
        assert!(remote_things(&r.html).is_empty());
        // The subject keeps the code whole; only the body spaces it. Another length is not spaced.
        assert!(
            rendered(Kind::VerifyEmail, "1234")
                .html
                .contains(">1234</p>")
        );
    }

    #[test]
    fn the_sign_up_attempt_email_is_as_designed() {
        let link = "https://account.orbyn.dev/sign-in";
        let r = rendered(
            Kind::SignUpAttempt,
            &format!("2026-11-07T09:41:30Z\n{link}"),
        );
        assert_eq!(
            r.subject,
            "Someone tried to create an Orbyn account with your email"
        );
        assert_eq!(
            r.text,
            format!(
                "Someone tried to create an Orbyn account with your email\n\n\
                 Someone tried to create a new Orbyn account with\n\
                 sam@example.com on Saturday 7 November 2026 at 09:41 UTC.\n\n\
                 If this was you, sign in instead:\nhttps://account.orbyn.dev/sign-in\n\n\
                 If it wasn't, you don't need to do anything. Nothing on\n\
                 your account changed, and no one can get in with your\n\
                 email address alone.\n\n{FOOTER_LINES}"
            )
        );
        common(&r.html);
        assert!(r.html.contains(">You already have an Orbyn account</h1>"));
        assert!(r.html.contains("Someone tried to create a new Orbyn account with sam@example.com on Saturday 7 November 2026 at 09:41 UTC."));
        assert!(r.html.contains("<b>If this was you,</b> sign in instead."));
        assert!(r.html.contains(">Sign in to Orbyn</a>"));
        assert!(r.html.contains("<b>If it wasn’t,</b> you don’t need to do anything. Nothing on your account changed, and no one can get in with your email address alone."));
        assert_eq!(remote_things(&r.html), [link]);
    }

    #[test]
    fn without_an_account_url_the_attempt_email_says_to_open_the_app() {
        let r = rendered(Kind::SignUpAttempt, "2026-11-07T09:41:30Z\n");
        assert_eq!(
            r.text,
            format!(
                "Someone tried to create an Orbyn account with your email\n\n\
                 Someone tried to create a new Orbyn account with\n\
                 sam@example.com on Saturday 7 November 2026 at 09:41 UTC.\n\n\
                 If this was you, open Orbyn and sign in with\n\
                 sam@example.com instead of creating a new account.\n\n\
                 If it wasn't, you don't need to do anything. Nothing on\n\
                 your account changed, and no one can get in with your\n\
                 email address alone.\n\n{FOOTER_LINES}"
            )
        );
        assert!(!r.text.contains("http"));
        assert!(r.html.contains("<b>If this was you,</b> open Orbyn and sign in with sam@example.com instead of creating a new account."));
        assert!(!r.html.contains("<a ") && !r.html.contains("sign in instead"));
        assert!(
            r.html
                .contains("<b>If it wasn’t,</b> you don’t need to do anything.")
        );
        assert!(remote_things(&r.html).is_empty());
        // A bare token, as an older queued message might carry, is not a link either.
        let old = rendered(Kind::DeletionScheduled, "2026-11-14T12:00:00Z\nabcDEF123");
        assert!(!old.html.contains("<a ") && !old.text.contains("abcDEF123"));
    }

    #[test]
    fn the_deletion_email_is_as_designed() {
        let link = "https://account.orbyn.dev/cancel-deletion#Zm9vYmFyLXRva2Vu";
        let r = rendered(
            Kind::DeletionScheduled,
            &format!("2026-11-14T12:00:00Z\n{link}"),
        );
        assert_eq!(
            r.subject,
            "Your Orbyn account will be deleted on 14 November"
        );
        assert_eq!(
            r.text,
            format!(
                "Your Orbyn account will be deleted on 14 November\n\n\
                 You asked to delete your Orbyn account, sam@example.com.\n\
                 It will be deleted on Saturday 14 November 2026 at 12:00 UTC,\n\
                 with everything in it in every Orbyn app. Until then,\n\
                 everything keeps working.\n\n\
                 Changed your mind? Cancel deletion:\n{link}\n\n\
                 This link works once and doesn't need you to sign in. You\n\
                 can also cancel from any device where you're signed in:\n\
                 Settings > Account > Cancel deletion.\n\n\
                 If you asked for this, there's nothing else to do. If you\n\
                 didn't, cancel now and then check your devices at\n\
                 account.orbyn.dev.\n\n{FOOTER_LINES}"
            )
        );
        common(&r.html);
        assert!(r.html.contains(">Your account will be deleted</h1>"));
        assert!(r.html.contains("You asked to delete your Orbyn account, sam@example.com. It will be deleted on <b>Saturday 14 November 2026 at 12:00 UTC</b>, with everything in it in every Orbyn app. Until then, everything keeps working."));
        assert!(r.html.contains("<b>Changed your mind?</b>"));
        assert!(r.html.contains(">Cancel deletion</a>"));
        assert!(r.html.contains("The button works once and doesn’t need you to sign in. You can also cancel from any device where you’re signed in: Settings › Account › Cancel deletion."));
        assert!(r.html.contains("If you asked for this, there’s nothing else to do. If you didn’t, cancel now and then check your devices at account.orbyn.dev."));
        // The link is the only address, and the token is in it only after the `#`.
        assert_eq!(remote_things(&r.html), [link]);
        for part in [&r.html, &r.text] {
            assert_eq!(part.matches("Zm9vYmFyLXRva2Vu").count(), 1);
            assert!(part.contains("cancel-deletion#Zm9vYmFyLXRva2Vu"));
            assert!(!part.contains("cancel-deletion?"), "no query string");
        }
        // A day below ten has no leading zero.
        let early = rendered(
            Kind::DeletionScheduled,
            &format!("2026-11-05T08:05:00Z\n{link}"),
        );
        assert_eq!(
            early.subject,
            "Your Orbyn account will be deleted on 5 November"
        );
        assert!(early.text.contains("Thursday 5 November 2026 at 08:05 UTC"));
    }

    #[test]
    fn without_an_account_url_the_deletion_email_says_where_to_cancel_in_the_app() {
        let r = rendered(Kind::DeletionScheduled, "2026-11-14T12:00:00Z\n");
        assert_eq!(
            r.text,
            format!(
                "Your Orbyn account will be deleted on 14 November\n\n\
                 You asked to delete your Orbyn account, sam@example.com.\n\
                 It will be deleted on Saturday 14 November 2026 at 12:00 UTC,\n\
                 with everything in it in every Orbyn app. Until then,\n\
                 everything keeps working.\n\n\
                 Changed your mind? Open Orbyn on any device where you're\n\
                 signed in and go to Settings > Account > Cancel deletion.\n\
                 You have until the date above.\n\n\
                 If you asked for this, there's nothing else to do. If you\n\
                 didn't, cancel now and then check your devices in\n\
                 Settings > Account > Devices.\n\n{FOOTER_LINES}"
            )
        );
        assert!(!r.html.contains("<a ") && !r.text.contains("http"));
        assert!(r.html.contains("<b>Changed your mind?</b> Open Orbyn on any device where you’re signed in and go to Settings › Account › Cancel deletion. You have until the date above."));
        assert!(r.html.contains("If you asked for this, there’s nothing else to do. If you didn’t, cancel now and then check your devices in Settings › Account › Devices."));
        assert!(remote_things(&r.html).is_empty());
    }

    #[test]
    fn a_message_without_its_value_cannot_be_rendered_and_there_is_no_expired_code_email() {
        assert_eq!(mail(Kind::VerifyEmail, None).render(), None);
        assert_eq!(mail(Kind::SignUpAttempt, None).render(), None);
        assert_eq!(
            mail(Kind::DeletionScheduled, Some("not a time\nhttps://x")).render(),
            None
        );
        assert!(!format!("{:?}", rendered(Kind::VerifyEmail, "123456")).contains("expired"));
    }

    #[test]
    fn what_a_person_types_is_escaped_in_the_html() {
        let mut m = mail(
            Kind::SignUpAttempt,
            Some("2026-11-07T09:41:30Z\nhttps://a.example/sign-in?x=1&y=\"2\""),
        );
        m.to = "a<b>&\"'@example.com".to_owned();
        let r = m.render().expect("renders");
        assert!(r.html.contains("a&lt;b&gt;&amp;&quot;&#39;@example.com"));
        assert!(!r.html.contains("<b>&"), "{}", r.html);
        assert!(
            r.html
                .contains("href=\"https://a.example/sign-in?x=1&amp;y=&quot;2&quot;\"")
        );
    }

    #[test]
    fn debug_shows_sizes_and_never_the_code_or_the_token() {
        let code = rendered(Kind::VerifyEmail, "482913");
        let shown = format!("{code:?}");
        assert!(
            !shown.contains("482913") && !shown.contains("Orbyn"),
            "{shown}"
        );
        let link = "https://account.orbyn.dev/cancel-deletion#TOKENTOKEN";
        let delete = rendered(
            Kind::DeletionScheduled,
            &format!("2026-11-14T12:00:00Z\n{link}"),
        );
        let shown = format!("{delete:?}");
        assert!(
            !shown.contains("TOKENTOKEN") && !shown.contains("sam@example.com"),
            "{shown}"
        );
        assert!(shown.contains("bytes"));
    }

    #[test]
    fn the_reason_a_message_cannot_be_built_names_no_person() {
        assert_eq!(
            mail(Kind::VerifyEmail, None).cannot_build_reason(),
            "the message couldn't be built (it has no code)"
        );
        assert_eq!(
            mail(Kind::SignUpAttempt, None).cannot_build_reason(),
            "the message couldn't be built (it has no time)"
        );
        assert_eq!(
            mail(Kind::DeletionScheduled, Some("later\n")).cannot_build_reason(),
            "the message couldn't be built (its time can't be read)"
        );
    }

    #[test]
    fn the_unused_account_email_is_as_designed() {
        let link = "https://account.example.com/delete-unused#tok";
        let r = rendered(Kind::DeleteUnused, link);
        assert_eq!(r.subject, "Delete your unused Orbyn account");
        assert_eq!(
            r.text,
            format!(
                "Delete your unused Orbyn account\n\n\
                 You asked to delete the Orbyn account sam@example.com so\n\
                 you can sign up again. It has nothing stored in it.\n\n\
                 Delete this account:\n{link}\n\n\
                 This link works once and expires in 24 hours. It doesn't need\n\
                 you to sign in. It only deletes an account with nothing\n\
                 stored in it. If the account has anything in it, nothing\n\
                 is deleted.\n\n\
                 If you didn't ask for this, ignore this email. Nothing\n\
                 happens unless the link is opened and the button pressed.\n\n{FOOTER_LINES}"
            )
        );
        common(&r.html);
        assert!(r.html.contains(">Delete your empty Orbyn account</h1>"));
        assert!(r.html.contains("You asked to delete the Orbyn account sam@example.com so you can sign up again. It has nothing stored in it."));
        assert!(
            r.html.contains(&format!("href=\"{link}\""))
                && r.html.contains(">Delete this account</a>")
        );
        // Red, as drawn; the other emails' buttons stay as they were.
        assert!(r.html.contains("background:#d42a2a;color:#ffffff"));
        assert!(!r.html.contains("background:#111111"));
        assert!(
            rendered(
                Kind::SignUpAttempt,
                "2026-11-14T12:00:00Z\nhttps://account.example.com/sign-in"
            )
            .html
            .contains("background:#111111")
        );
        assert!(r.html.contains("The button works once and expires in 24 hours. It doesn’t need you to sign in. It only deletes an account with nothing stored in it. If the account has anything in it, nothing is deleted."));
        assert!(r.html.contains("If you didn’t ask for this, ignore this email. Nothing happens unless the button is pressed."));
        assert_eq!(remote_things(&r.html), vec![link.to_owned()]);
        // The lifetime comes from the constant, not from the text.
        assert_eq!(
            crate::accounts::DELETE_UNUSED_TTL,
            std::time::Duration::from_secs(24 * 3600)
        );
    }

    #[test]
    fn without_an_account_url_the_unused_account_email_has_no_link() {
        let r = rendered(Kind::DeleteUnused, "");
        assert_eq!(r.subject, "Delete your unused Orbyn account");
        assert_eq!(
            r.text,
            format!(
                "Your empty Orbyn account\n\n\
                 You asked to delete the Orbyn account sam@example.com so\n\
                 you can sign up again. It has nothing stored in it.\n\n\
                 This server has no account site, so there's no link. Ask\n\
                 whoever runs this server to delete the empty account\n\
                 sam@example.com. Then sign up again.\n\n\
                 If you didn't ask for this, you can ignore this email.\n\n{FOOTER_LINES}"
            )
        );
        common(&r.html);
        assert!(r.html.contains(">Your empty Orbyn account</h1>"));
        assert!(r.html.contains("This server has no account site, so there’s no link. Ask whoever runs this server to delete the empty account sam@example.com. Then sign up again."));
        assert!(
            r.html
                .contains("If you didn’t ask for this, you can ignore this email.")
        );
        assert!(!r.html.contains("<a "));
        assert!(remote_things(&r.html).is_empty());
    }
}
