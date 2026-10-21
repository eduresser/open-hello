use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use zbus::zvariant::Value;
use zbus::Connection;

use crate::dbus_service::{Action, AuthFuture, Authorizer, Caller};

const POLKIT_NAME: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const ALLOW_USER_INTERACTION: u32 = 1;

pub type PolkitFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;

pub trait PolkitClient: Send + Sync {
    fn is_authorized<'a>(&'a self, action_id: &'a str, bus_name: &'a str) -> PolkitFuture<'a>;
}

pub struct DbusPolkit;

impl PolkitClient for DbusPolkit {
    fn is_authorized<'a>(&'a self, action_id: &'a str, bus_name: &'a str) -> PolkitFuture<'a> {
        Box::pin(async move {
            let system = Connection::system().await.map_err(|e| format!("cannot reach the system bus: {e}"))?;
            let subject = ("system-bus-name", HashMap::from([("name", Value::from(bus_name))]));
            let details: HashMap<&str, &str> = HashMap::new();
            let reply = system
                .call_method(
                    Some(POLKIT_NAME),
                    POLKIT_PATH,
                    Some(POLKIT_INTERFACE),
                    "CheckAuthorization",
                    &(subject, action_id, details, ALLOW_USER_INTERACTION, ""),
                )
                .await
                .map_err(|e| format!("polkit CheckAuthorization failed: {e}"))?;
            let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) =
                reply.body().deserialize().map_err(|e| format!("unexpected polkit reply: {e}"))?;
            Ok(authorized)
        })
    }
}

pub struct PolkitAuthorizer {
    client: Arc<dyn PolkitClient>,
}

impl PolkitAuthorizer {
    pub fn new(client: Arc<dyn PolkitClient>) -> Self {
        Self { client }
    }
}

impl Authorizer for PolkitAuthorizer {
    fn authorize<'a>(&'a self, action: Action, caller: &'a Caller, target_uid: u32) -> AuthFuture<'a> {
        Box::pin(async move {
            if caller.uid != 0 && caller.uid != target_uid {
                return Err(format!("uid {} may not act on the biometric data of uid {target_uid}", caller.uid));
            }
            match self.client.is_authorized(action.polkit_id(), &caller.bus_name).await {
                Ok(true) => Ok(()),
                Ok(false) => Err("polkit denied the request".to_string()),
                Err(problem) => Err(format!("polkit unavailable, request refused: {problem}")),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct ScriptedPolkit {
        answer: Result<bool, String>,
        asked: Mutex<Vec<String>>,
    }

    impl PolkitClient for ScriptedPolkit {
        fn is_authorized<'a>(&'a self, action_id: &'a str, _: &'a str) -> PolkitFuture<'a> {
            self.asked.lock().unwrap().push(action_id.to_string());
            let answer = self.answer.clone();
            Box::pin(async move { answer })
        }
    }

    fn authorizer(answer: Result<bool, String>) -> (PolkitAuthorizer, Arc<ScriptedPolkit>) {
        let client = Arc::new(ScriptedPolkit { answer, asked: Mutex::new(vec![]) });
        (PolkitAuthorizer::new(client.clone()), client)
    }

    fn caller(uid: u32) -> Caller {
        Caller { bus_name: ":1.42".into(), uid }
    }

    #[test]
    fn owner_is_allowed_only_when_polkit_agrees() {
        let (allow, client) = authorizer(Ok(true));
        assert!(async_io::block_on(allow.authorize(Action::EnrollBegin, &caller(1000), 1000)).is_ok());
        assert_eq!(*client.asked.lock().unwrap(), vec!["io.openhello.biometrics.enroll-begin"]);
        let (deny, _) = authorizer(Ok(false));
        assert!(async_io::block_on(deny.authorize(Action::Purge, &caller(1000), 1000)).is_err());
    }

    #[test]
    fn other_users_are_refused_without_consulting_polkit() {
        let (allow, client) = authorizer(Ok(true));
        let result = async_io::block_on(allow.authorize(Action::EnrollBegin, &caller(1001), 1000));
        assert!(result.unwrap_err().contains("may not act"));
        assert!(client.asked.lock().unwrap().is_empty());
    }

    #[test]
    fn root_may_act_on_any_uid_subject_to_polkit() {
        let (allow, client) = authorizer(Ok(true));
        assert!(async_io::block_on(allow.authorize(Action::Purge, &caller(0), 1000)).is_ok());
        assert_eq!(client.asked.lock().unwrap().len(), 1);
    }

    #[test]
    fn polkit_failures_refuse_the_request() {
        let (broken, _) = authorizer(Err("no authority".into()));
        let error = async_io::block_on(broken.authorize(Action::EnrollCommit, &caller(1000), 1000)).unwrap_err();
        assert!(error.contains("refused"));
    }

    #[test]
    fn every_action_has_a_polkit_rule_in_the_shipped_policy_file() {
        let policy = include_str!("../io.openhello.Biometrics1.policy");
        for action in [Action::EnrollBegin, Action::EnrollCapture, Action::EnrollCommit, Action::EnrollDiscard, Action::Purge] {
            assert!(policy.contains(&format!("<action id=\"{}\">", action.polkit_id())), "{action:?}");
        }
        assert!(!policy.contains("<allow_any>yes</allow_any>"));
    }
}
