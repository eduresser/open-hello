use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::thread;

const DISTROS: [&str; 4] = ["opensuse", "fedora", "debian", "arch"];
const COVERED: [&str; 3] = ["opensuse", "debian", "arch"];
const PASSWORD: &str = "Correct-Horse-7";
const STALE: &str = "Stale-Password-1";
const PAM_SUCCESS: &str = "0";
const PAM_AUTH_ERR: &str = "7";

#[derive(Debug, Default)]
struct Scenario {
    prompts: Vec<String>,
    auth: Option<String>,
    setcred: Option<String>,
    log: Vec<String>,
}

impl Scenario {
    fn logged(&self, line: &str) -> bool {
        self.log.iter().any(|l| l == line)
    }
}

struct Run {
    output: String,
    scenarios: HashMap<String, Scenario>,
}

impl Run {
    fn scenario(&self, distro: &str, name: &str) -> &Scenario {
        self.scenarios.get(name).unwrap_or_else(|| {
            panic!(
                "{distro}: scenario {name} missing from output:\n{}",
                self.output
            )
        })
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures() -> PathBuf {
    repo_root().join("tests/fixtures/pam-stacks")
}

fn image(distro: &str) -> String {
    format!("localhost/openhello-pamstack-{distro}")
}

fn require_podman() {
    match Command::new("podman").arg("--version").output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => panic!(
            "podman is installed but `podman --version` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => panic!(
            "podman is required to run the real distribution PAM stacks (install podman): {e}"
        ),
    }
}

fn build_image(distro: &str) {
    let out = Command::new("podman")
        .args(["build", "-q", "-t", &image(distro), "-f"])
        .arg(fixtures().join(format!("{distro}.Containerfile")))
        .arg(fixtures())
        .output()
        .expect("podman build did not start");
    assert!(
        out.status.success(),
        "{distro}: podman build failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn run_container(distro: &str) -> String {
    build_image(distro);
    let cli = PathBuf::from(env!("CARGO_BIN_EXE_openhello-cli"));
    let out = Command::new("podman")
        .args(["run", "--rm", "-v"])
        .arg(format!(
            "{}:/src:ro,z",
            repo_root().canonicalize().unwrap().display()
        ))
        .arg("-v")
        .arg(format!("{}:/opt/openhello-cli:ro,z", cli.display()))
        .arg(image(distro))
        .args(["sh", "/src/tests/fixtures/pam-stacks/run.sh", distro])
        .output()
        .expect("podman run did not start");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{distro}: scenario driver failed:\n{text}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

fn parse(output: &str) -> HashMap<String, Scenario> {
    let mut scenarios = HashMap::new();
    let mut current: Option<(String, Scenario)> = None;
    for line in output.lines() {
        if let Some(name) = line.strip_prefix("SCENARIO ") {
            current = Some((name.to_string(), Scenario::default()));
        } else if line.starts_with("END ") {
            if let Some((name, scenario)) = current.take() {
                scenarios.insert(name, scenario);
            }
        } else if let Some((_, scenario)) = current.as_mut() {
            if let Some(prompt) = line.strip_prefix("PROMPT ") {
                scenario.prompts.push(prompt.to_string());
            } else if let Some(rc) = line.strip_prefix("AUTH ") {
                scenario.auth = Some(rc.to_string());
            } else if let Some(rc) = line.strip_prefix("SETCRED ") {
                scenario.setcred = Some(rc.to_string());
            } else if let Some(entry) = line.strip_prefix("LOG ") {
                scenario.log.push(entry.to_string());
            }
        }
    }
    scenarios
}

fn runs() -> &'static HashMap<&'static str, Run> {
    static RUNS: OnceLock<HashMap<&'static str, Run>> = OnceLock::new();
    RUNS.get_or_init(|| {
        require_podman();
        let handles: Vec<_> = DISTROS
            .iter()
            .map(|&d| (d, thread::spawn(move || run_container(d))))
            .collect();
        handles
            .into_iter()
            .map(|(d, h)| {
                let output = h
                    .join()
                    .unwrap_or_else(|_| panic!("{d}: container run panicked"));
                let scenarios = parse(&output);
                (d, Run { output, scenarios })
            })
            .collect()
    })
}

fn release_problems(distro: &str, name: &str, s: &Scenario) -> Vec<String> {
    let mut problems = Vec::new();
    if s.auth.as_deref() != Some(PAM_SUCCESS) {
        problems.push(format!(
            "{distro} {name}: not granted (pam_authenticate = {:?})",
            s.auth
        ));
    }
    if !s.prompts.is_empty() {
        problems.push(format!("{distro} {name}: prompted {:?}", s.prompts));
    }
    if !s.logged(&format!("KEYRING authenticate authtok={PASSWORD}")) {
        problems.push(format!("{distro} {name}: keyring stub saw {:?}", s.log));
    }
    problems
}

// @spec:AC-090
#[test]
fn released_password_signs_in_without_prompt_on_each_covered_distribution_stack() {
    let runs = runs();
    let problems: Vec<String> = COVERED
        .iter()
        .flat_map(|d| {
            release_problems(
                d,
                "packaged:release",
                runs[d].scenario(d, "packaged:release"),
            )
        })
        .collect();
    assert!(
        problems.is_empty(),
        "the released password did not sign in silently on every stack:\n{}",
        problems.join("\n")
    );
}

#[test]
fn stale_token_fails_without_prompt_and_setcred_never_sees_the_typed_password() {
    let runs = runs();
    let placed = [
        ("opensuse", "packaged"),
        ("debian", "packaged"),
        ("arch", "packaged"),
        ("fedora", "manual-password-auth"),
    ];
    for (distro, placement) in placed {
        let run = &runs[distro];
        let release = run.scenario(distro, &format!("{placement}:release"));
        assert!(
            release_problems(distro, placement, release).is_empty(),
            "{}",
            run.output
        );

        let stale = run.scenario(distro, &format!("{placement}:wrong-token"));
        assert_eq!(
            stale.auth.as_deref(),
            Some(PAM_AUTH_ERR),
            "{distro}: {}",
            run.output
        );
        assert!(stale.prompts.is_empty(), "{distro}: {}", run.output);
        assert!(stale.logged(&format!("OPENHELLO authenticate authtok={STALE}")));

        let typed = run.scenario(distro, &format!("{placement}:typed"));
        assert_eq!(
            typed.auth.as_deref(),
            Some(PAM_SUCCESS),
            "{distro}: {}",
            run.output
        );
        assert_eq!(
            typed.setcred.as_deref(),
            Some(PAM_SUCCESS),
            "{distro}: {}",
            run.output
        );
        assert_eq!(typed.prompts.len(), 1, "{distro}: {}", run.output);
        assert!(
            typed.logged("OPENHELLO authenticate authtok=(unset)"),
            "{distro}: {}",
            run.output
        );
        assert!(
            typed.logged("OPENHELLO setcred authtok=(unset)"),
            "{distro}: {}",
            run.output
        );
    }

    let fedora = &runs["fedora"];
    assert!(fedora.output.contains("ENABLE rc=3"), "{}", fedora.output);
    let packaged = fedora.scenario("fedora", "packaged:release");
    assert_eq!(packaged.prompts.len(), 1, "{}", fedora.output);
    assert!(
        !packaged.log.iter().any(|l| l.starts_with("OPENHELLO")),
        "{}",
        fedora.output
    );
}
