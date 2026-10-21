use std::ffi::CString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Remote,
    NotLocal,
    ServiceNotAllowed,
    NoUser,
    NoCredentialFile,
    CredentialFileUntrusted,
    OpenhellodUnavailable,
    KeydUnavailable,
    FaceRefused,
    SignatureInvalid,
    Success,
}

impl Reason {
    #[cfg(test)]
    pub const ALL: [Reason; 11] = [
        Reason::Remote,
        Reason::NotLocal,
        Reason::ServiceNotAllowed,
        Reason::NoUser,
        Reason::NoCredentialFile,
        Reason::CredentialFileUntrusted,
        Reason::OpenhellodUnavailable,
        Reason::KeydUnavailable,
        Reason::FaceRefused,
        Reason::SignatureInvalid,
        Reason::Success,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Reason::Remote => "remote",
            Reason::NotLocal => "not-local",
            Reason::ServiceNotAllowed => "service-not-allowed",
            Reason::NoUser => "no-user",
            Reason::NoCredentialFile => "no-credential-file",
            Reason::CredentialFileUntrusted => "credential-file-untrusted",
            Reason::OpenhellodUnavailable => "openhellod-unavailable",
            Reason::KeydUnavailable => "keyd-unavailable",
            Reason::FaceRefused => "face-refused",
            Reason::SignatureInvalid => "signature-invalid",
            Reason::Success => "success",
        }
    }
}

pub fn line(reason: Reason, service: &str) -> String {
    let service: String = service
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(64)
        .collect();
    format!("reason={} service={service}", reason.code())
}

pub fn report(enabled: bool, sink: &dyn Fn(&str), reason: Reason, service: &str) {
    if enabled {
        sink(&line(reason, service));
    }
}

pub fn syslog(message: &str) {
    let Ok(text) = CString::new(message) else {
        return;
    };
    unsafe {
        libc::openlog(c"pam_openhello".as_ptr(), libc::LOG_PID, libc::LOG_AUTHPRIV);
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_INFO,
            c"%s".as_ptr(),
            text.as_ptr(),
        );
        libc::closelog();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    // @covers:AC-028-pam-local-session
    #[test]
    fn every_reason_writes_exactly_one_line_with_its_code_and_the_service() {
        for reason in Reason::ALL {
            let lines = RefCell::new(Vec::new());
            let sink = |l: &str| lines.borrow_mut().push(l.to_string());
            report(true, &sink, reason, "kde");
            assert_eq!(
                *lines.borrow(),
                vec![format!("reason={} service=kde", reason.code())]
            );
        }
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn nothing_is_written_without_the_debug_argument() {
        let lines = RefCell::new(Vec::new());
        let sink = |l: &str| lines.borrow_mut().push(l.to_string());
        for reason in Reason::ALL {
            report(false, &sink, reason, "kde");
        }
        assert!(lines.borrow().is_empty());
    }

    // @covers:AC-028-pam-local-session
    #[test]
    fn the_service_name_cannot_inject_log_fields_or_control_characters() {
        let text = line(Reason::Success, "sudo\nreason=forged user=x");
        assert!(!text.contains('\n'));
        assert_eq!(text, "reason=success service=sudoreasonforgeduserx");
    }

    #[test]
    fn codes_are_unique() {
        let mut codes: Vec<_> = Reason::ALL.iter().map(|r| r.code()).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), Reason::ALL.len());
    }
}
