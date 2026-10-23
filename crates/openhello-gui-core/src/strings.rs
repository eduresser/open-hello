use crate::wizard::FailureCause;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    PortugueseBr,
}

impl Language {
    pub fn detect() -> Self {
        Self::from_env(|name| std::env::var(name).ok())
    }

    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Self {
        let locale = ["LC_ALL", "LC_MESSAGES", "LANG"].iter().filter_map(|name| get(name)).find(|value| !value.is_empty());
        match locale {
            Some(value) if value.to_ascii_lowercase().starts_with("pt") => Language::PortugueseBr,
            _ => Language::English,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Text {
    WelcomeTitle,
    WelcomeBody,
    GetStarted,
    Next,
    Done,
    Close,
    Cancel,
    TryAgain,
    IdentityTitle,
    IdentityBody,
    PinTitle,
    PinBody,
    PinLabel,
    PinConfirmLabel,
    PinMismatch,
    PinInvalid,
    CaptureTitle,
    RecoveryTitle,
    RecoveryBody,
    DoneTitle,
    DoneBody,
    GuidanceAccepted,
    GuidanceNoFace,
    GuidanceMoveLeft,
    GuidanceMoveRight,
    GuidanceMoveUp,
    GuidanceMoveDown,
    GuidanceTooClose,
    GuidanceTooFar,
    GuidanceTooDark,
    GuidanceTooBright,
    GuidanceLookForward,
    GuidanceBlurred,
    GuidanceOccluded,
    GuidanceNeutral,
    TimeoutTitle,
    TimeoutBody,
    CameraBusyTitle,
    CameraBusyBody,
    NoCameraTitle,
    NoCameraBody,
    SensorStuckTitle,
    SensorStuckBody,
    TpmTitle,
    TpmBody,
    AuthDeniedTitle,
    AuthDeniedBody,
    KeyFailedTitle,
    KeyFailedBody,
    OtherTitle,
    OtherBody,
}

impl Text {
    fn pair(self) -> (&'static str, &'static str) {
        match self {
            Text::WelcomeTitle => ("Welcome to OpenHello", "Bem-vindo ao OpenHello"),
            Text::WelcomeBody => (
                "Your device just got more personal. Start using your face to unlock your device, verify your identity, and buy things in the Store.",
                "Seu dispositivo ficou mais pessoal. Comece a usar sua face para desbloquear o dispositivo, verificar sua identidade e comprar na Store.",
            ),
            Text::GetStarted => ("Get started", "Começar agora"),
            Text::Next => ("Next", "Avançar"),
            Text::Done => ("Done", "Concluído"),
            Text::Close => ("Close", "Fechar"),
            Text::Cancel => ("Cancel", "Cancelar"),
            Text::TryAgain => ("Try again", "Tentar novamente"),
            Text::IdentityTitle => ("Confirm it's you", "Confirme que é você"),
            Text::IdentityBody => (
                "Enter your system password when asked, to confirm that you are the owner of this account.",
                "Digite a senha do sistema quando for solicitada, para confirmar que você é o dono desta conta.",
            ),
            Text::PinTitle => ("Create a PIN", "Crie um PIN"),
            Text::PinBody => (
                "Create a PIN to use if face recognition is not available. You may never need it, but it will serve as a backup just in case. Once you set up your PIN, you will be able to sign in with your face.",
                "Crie um PIN para usar se o reconhecimento facial não estiver disponível. Talvez você nunca precise usá-lo, mas ele servirá como um backup, por via das dúvidas. Uma vez configurado seu PIN, você poderá entrar com o reconhecimento facial.",
            ),
            Text::PinLabel => ("PIN", "PIN"),
            Text::PinConfirmLabel => ("Confirm PIN", "Confirmar PIN"),
            Text::PinMismatch => ("These PINs don’t match.", "Esses PINs não correspondem."),
            Text::PinInvalid => (
                "The PIN must have 6 to 32 printable characters.",
                "O PIN deve ter de 6 a 32 caracteres imprimíveis.",
            ),
            Text::CaptureTitle => ("Look at the camera", "Olhe para a câmera"),
            Text::RecoveryTitle => ("Recovery code", "Código de recuperação"),
            Text::RecoveryBody => (
                "This recovery code is shown only once. Write it down and keep it in a safe place: it is the only way to get back in if the TPM fails.",
                "Este código de recuperação é mostrado uma única vez. Anote-o e guarde-o em um lugar seguro: é a única forma de voltar a entrar se o TPM falhar.",
            ),
            Text::DoneTitle => ("All set", "Tudo pronto"),
            Text::DoneBody => (
                "Well done! You are ready to start using OpenHello! Use your face the next time you want to unlock your device.",
                "Muito bem! Você está pronto para começar a usar o OpenHello! Use a face na próxima vez que quiser desbloquear seu dispositivo.",
            ),
            Text::GuidanceAccepted => ("Keep looking directly at your camera.", "Continue olhando diretamente para a câmera."),
            Text::GuidanceNoFace => (
                "We couldn’t detect your face, please make sure there is enough light and your face is centered in the frame.",
                "Não conseguimos detectar o seu rosto, confira se há luz suficiente e seu rosto está centrado na moldura.",
            ),
            Text::GuidanceMoveLeft => ("Move a little to your left", "Mova-se um pouco para a esquerda"),
            Text::GuidanceMoveRight => ("Move a little to your right", "Mova-se um pouco para a direita"),
            Text::GuidanceMoveUp => ("Move up a little", "Mova-se um pouco para cima"),
            Text::GuidanceMoveDown => ("Move down a little", "Mova-se um pouco para baixo"),
            Text::GuidanceTooClose => ("Too close! Move a little farther away.", "Muito próximo! Afaste-se um pouco mais."),
            Text::GuidanceTooFar => ("Too far! Move a bit closer.", "Muito distante! Aproxime-se um pouco."),
            Text::GuidanceTooDark => (
                "Too dark! Turn on some lights or move somewhere brighter.",
                "Muito escuro! Acenda algumas luzes ou vá para um lugar mais claro.",
            ),
            Text::GuidanceTooBright => (
                "Too bright! Turns off some lights or go inside.",
                "Muito claro! Apague algumas luzes ou vá para um lugar fechado.",
            ),
            Text::GuidanceLookForward => ("Keep looking forward, facing the camera.", "Continue olhando para frente, de frente para a câmera."),
            Text::GuidanceBlurred => ("Hold still: the image is not sharp enough", "Fique parado: a imagem não está nítida o bastante"),
            Text::GuidanceOccluded => (
                "We’re having trouble seeing you. Try removing anything that may be blocking your face.",
                "Não estamos conseguindo ver você direito. Remova o que possa estar bloqueando sua face.",
            ),
            Text::GuidanceNeutral => ("Stay in front of the camera and hold still.", "Fique diante da câmera e permaneça parado."),
            Text::TimeoutTitle => ("Face setup timed out", "A configuração do rosto expirou"),
            Text::TimeoutBody => (
                "We could not collect enough samples in 20 seconds. Make sure there is enough light and your face is centered in the frame, then try again.",
                "Não foi possível coletar amostras suficientes em 20 segundos. Confira se há luz suficiente e se seu rosto está centrado na moldura, e tente novamente.",
            ),
            Text::CameraBusyTitle => ("Camera in use", "Câmera em uso"),
            Text::CameraBusyBody => (
                "Camera is currently in use by another app. Close the app and try again.",
                "A câmera está sendo usada por outro aplicativo. Feche o aplicativo e tente novamente.",
            ),
            Text::NoCameraTitle => ("Camera not available", "Câmera indisponível"),
            Text::NoCameraBody => (
                "Couldn’t turn on the camera. Make sure it’s working properly.",
                "Não foi possível ligar a câmera. Verifique se ela está funcionando corretamente.",
            ),
            Text::SensorStuckTitle => ("Infrared camera stuck", "Câmera infravermelha travada"),
            Text::SensorStuckBody => (
                "The infrared stream is stuck: power the computer off completely and try again.",
                "O fluxo infravermelho travou: desligue o computador completamente e tente novamente.",
            ),
            Text::TpmTitle => ("TPM not available", "TPM indisponível"),
            Text::TpmBody => (
                "The TPM is unavailable. Check that it is enabled in the firmware and try again.",
                "O TPM está indisponível. Verifique se ele está ativado no firmware e tente novamente.",
            ),
            Text::AuthDeniedTitle => ("Identity not confirmed", "Identidade não confirmada"),
            Text::AuthDeniedBody => (
                "The system password was not confirmed, so nothing was saved. Try again.",
                "A senha do sistema não foi confirmada, então nada foi salvo. Tente novamente.",
            ),
            Text::KeyFailedTitle => ("Login key not created", "Chave de login não criada"),
            Text::KeyFailedBody => (
                "Your face was saved, but the login key could not be created, so signing in with your face will not work yet. Try again to create the key.",
                "Seu rosto foi salvo, mas não foi possível criar a chave de login, então entrar com o rosto ainda não vai funcionar. Tente novamente para criar a chave.",
            ),
            Text::OtherTitle => ("Something went wrong", "Algo deu errado"),
            Text::OtherBody => (
                "The setup could not be completed and nothing was saved. Try again.",
                "Não foi possível concluir a configuração e nada foi salvo. Tente novamente.",
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strings {
    language: Language,
}

impl Strings {
    pub fn new(language: Language) -> Self {
        Self { language }
    }

    pub fn language(&self) -> Language {
        self.language
    }

    pub fn get(&self, text: Text) -> &'static str {
        let (english, portuguese) = text.pair();
        match self.language {
            Language::English => english,
            Language::PortugueseBr => portuguese,
        }
    }

    pub fn guidance(&self, verdict: &str) -> &'static str {
        self.get(guidance_text(verdict))
    }

    pub fn progress(&self, filled: u32, required: u32) -> String {
        match self.language {
            Language::English => format!("{filled} of {required}"),
            Language::PortugueseBr => format!("{filled} de {required}"),
        }
    }

    pub fn failure_title(&self, cause: FailureCause) -> &'static str {
        self.get(failure_texts(cause).0)
    }

    pub fn failure_explanation(&self, cause: FailureCause) -> &'static str {
        self.get(failure_texts(cause).1)
    }
}

fn guidance_text(verdict: &str) -> Text {
    match verdict {
        "accepted" | "too-soon" => Text::GuidanceAccepted,
        "no-face" => Text::GuidanceNoFace,
        "move-left" => Text::GuidanceMoveLeft,
        "move-right" => Text::GuidanceMoveRight,
        "move-up" => Text::GuidanceMoveUp,
        "move-down" => Text::GuidanceMoveDown,
        "too-close" => Text::GuidanceTooClose,
        "too-far" => Text::GuidanceTooFar,
        "too-dark" => Text::GuidanceTooDark,
        "too-bright" => Text::GuidanceTooBright,
        "yaw-out-of-range" => Text::GuidanceLookForward,
        "blurred" => Text::GuidanceBlurred,
        "occluded" => Text::GuidanceOccluded,
        _ => Text::GuidanceNeutral,
    }
}

fn failure_texts(cause: FailureCause) -> (Text, Text) {
    match cause {
        FailureCause::Timeout => (Text::TimeoutTitle, Text::TimeoutBody),
        FailureCause::CameraBusy => (Text::CameraBusyTitle, Text::CameraBusyBody),
        FailureCause::NoCamera => (Text::NoCameraTitle, Text::NoCameraBody),
        FailureCause::SensorStuck => (Text::SensorStuckTitle, Text::SensorStuckBody),
        FailureCause::TpmUnavailable => (Text::TpmTitle, Text::TpmBody),
        FailureCause::AuthDenied => (Text::AuthDeniedTitle, Text::AuthDeniedBody),
        FailureCause::KeyFailed => (Text::KeyFailedTitle, Text::KeyFailedBody),
        FailureCause::Other => (Text::OtherTitle, Text::OtherBody),
    }
}
