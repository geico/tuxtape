mod nist_api_types;
mod rate_limiter;

use color_eyre::{eyre::eyre, Result};
use git2::{Oid, Repository};
use nist_api_types::{NistResponse, Vulnerability};
use rate_limiter::RateLimiter;
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const CACHE_PATH: &str = concat!(env!("HOME"), "/.cache/tuxtape-server");
const GIT_PATH: &str = const_format::concatcp!(CACHE_PATH, "/git");
const CVE_REPO_PATH: &str = const_format::concatcp!(GIT_PATH, "/vulns");
const LINUX_REPO_PATH: &str = const_format::concatcp!(GIT_PATH, "/linux");
const DB_PATH: &str = const_format::concatcp!(CACHE_PATH, "/db.db3");
const NIST_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

fn main() -> anyhow::Result<(), anyhow::Error> {
    println!("Opening database");
    if !Path::new(CACHE_PATH).exists() {
        println!("Cache dir '{}' does not exist. Creating.", CACHE_PATH);
        std::fs::create_dir_all(CACHE_PATH)?;
    }
    let mut db = rusqlite::Connection::open(DB_PATH)?;

    let db_initializing = !db_tables_exist(&db);
    if db_initializing {
        println!("Database not found. Creating.");
        create_database(&db)?;
    }
    println!("Database exists.");

    sync_repos();
    update_database(&mut db, db_initializing)?;

    println!("Done.");

    Ok(())
}

fn update_database(
    db: &mut rusqlite::Connection,
    db_initializing: bool,
) -> anyhow::Result<(), anyhow::Error> {
    let based_on_vulns_commit = Repository::open(CVE_REPO_PATH)?
        .revparse("HEAD")?
        .from()
        .unwrap()
        .id()
        .to_string();

    let last_vulns_commit = fetch_last_vulns_commit(db)?;
    let mut cves = fetch_cves(last_vulns_commit.as_deref())?;
    fetch_nist(&mut cves, db_initializing, None);
    write_to_database(db, &cves, based_on_vulns_commit.as_str())
}

/// Fetch the last vulns commit this was ran against from the database
fn fetch_last_vulns_commit(db: &mut rusqlite::Connection) -> rusqlite::Result<Option<String>> {
    db.prepare("SELECT based_on_vulns_commit FROM meta")?
        .query_map([], |row| row.get::<_, String>(0))?
        .last()
        .transpose()
}

fn write_to_database(
    db: &mut rusqlite::Connection,
    cves: &Vec<Cve>,
    based_on_vulns_commit: &str,
) -> anyhow::Result<(), anyhow::Error> {
    println!("Updating database");

    let tx = db.transaction()?;

    for cve in cves {
        tx.execute(
            "REPLACE INTO cve (name, severity, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, description) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, $9, $10, $11)",
            rusqlite::params![cve.name, cve.severity, cve.attack_vector, cve.attack_complexity, cve.privileges_required, cve.user_interaction, cve.scope, cve.confidentiality_impact, cve.integrity_impact, cve.availability_impact, cve.description],
        )?;

        for instance in &cve.instances {
            let instance_title = format!(
                "{}-{}.{}.{}-{}",
                cve.name,
                instance.introduced.major,
                instance.introduced.minor,
                instance.introduced.patch,
                instance
                    .fixed_commit_prefix
                    .as_ref()
                    .unwrap_or(&"".to_string())
            );

            tx.execute(
                "REPLACE INTO cve_instance 
                    (title, cve, version_introduced_major, version_introduced_minor, version_introduced_patch, version_fixed_major, version_fixed_minor, version_fixed_patch, fixed_commit_prefix, patch) 
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)", 
                    rusqlite::params![
                        instance_title,
                        cve.name,
                        instance.introduced.major,
                        instance.introduced.minor,
                        instance.introduced.patch,
                        instance.fixed.as_ref().map(|fixed| fixed.major),
                        instance.fixed.as_ref().map(|fixed| fixed.minor),
                        instance.fixed.as_ref().map(|fixed| fixed.patch),
                        instance.fixed_commit_prefix,
                        instance.patch
                    ]
            )?;

            if let Some(affected_files) = instance.affected_files.as_ref() {
                for file_path in affected_files {
                    tx.execute(
                        "REPLACE INTO cve_instance_affected_file
                            (cve_instance, file_path) 
                            VALUES (?1, ?2)",
                        rusqlite::params![instance_title, file_path],
                    )?;
                }
            }
        }
    }

    // Remove previous meta entry
    tx.execute("DELETE FROM meta", [])?;

    let last_run_utc = chrono::Utc::now().to_string();
    tx.execute(
        "REPLACE INTO meta (based_on_vulns_commit, last_run_utc) VALUES (?1, ?2)",
        rusqlite::params![based_on_vulns_commit, last_run_utc],
    )?;

    tx.commit()?;

    Ok(())
}

fn db_tables_exist(db: &rusqlite::Connection) -> bool {
    // Assume tables exist, disprove with AND
    let mut tables_exist = true;

    // If any of the following are errors, we know that the database is invalid
    tables_exist = db.prepare("SELECT * FROM cve;").is_ok() && tables_exist;
    tables_exist = db.prepare("SELECT * FROM cve_instance;").is_ok() && tables_exist;
    tables_exist = db
        .prepare("SELECT * FROM cve_instance_affected_file;")
        .is_ok()
        && tables_exist;
    tables_exist = db.prepare("SELECT * FROM meta;").is_ok() && tables_exist;
    tables_exist = db.prepare("SELECT * FROM kernel_config;").is_ok() && tables_exist;
    tables_exist = db.prepare("SELECT * FROM kernel_file;").is_ok() && tables_exist;

    tables_exist
}

fn create_database(db: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // TODO - error handling
    let sql = "CREATE TABLE IF NOT EXISTS cve (
        name                        TEXT NOT NULL PRIMARY KEY,
        severity                    REAL,
        attack_vector               TEXT,
        attack_complexity           TEXT,
        privileges_required         TEXT,
        user_interaction            TEXT,
        scope                       TEXT,
        confidentiality_impact      TEXT,
        integrity_impact            TEXT,
        availability_impact         TEXT,
        description                 TEXT
    )";
    let _ = db.execute(sql, ())?;

    let sql = "CREATE TABLE IF NOT EXISTS cve_instance (
        title                       TEXT NOT NULL PRIMARY KEY,
        cve                         TEXT NOT NULL,
        version_introduced_major    INTEGER NOT NULL,
        version_introduced_minor    INTEGER NOT NULL,
        version_introduced_patch    INTEGER,
        version_fixed_major         INTEGER,
        version_fixed_minor         INTEGER,
        version_fixed_patch         INTEGER,
        fixed_commit_prefix         TEXT,
        patch                       BLOB,
        FOREIGN KEY(cve) REFERENCES cve(name)
    )";
    let _ = db.execute(sql, ())?;

    let sql = "CREATE TABLE IF NOT EXISTS cve_instance_affected_file (
        cve_instance                TEXT NOT NULL,
        file_path                   TEXT NOT NULL,
        FOREIGN KEY(cve_instance) REFERENCES cve_instance(title)
    )";
    let _ = db.execute(sql, ())?;

    let sql = "CREATE TABLE IF NOT EXISTS meta (
        based_on_vulns_commit             TEXT NOT NULL PRIMARY KEY,
        last_run_utc                      TEXT NOT NULL
    )";
    let _ = db.execute(sql, ())?;

    let sql = "CREATE TABLE IF NOT EXISTS kernel_config (
        config_name                 TEXT NOT NULL PRIMARY KEY,
        major                       INTEGER NOT NULL,
        minor                       INTEGER NOT NULL,
        patch                       INTEGER,
        config_file                 BLOB NOT NULL
    )";
    let _ = db.execute(sql, ())?;

    let sql = "CREATE TABLE IF NOT EXISTS kernel_file (
        file_path                   TEXT NOT NULL,
        config_name                 TEXT NOT NULL,
        FOREIGN KEY(config_name) REFERENCES kernel_config(config_name)
    )";
    let _ = db.execute(sql, ())?;

    Ok(())
}

fn sync_repos() {
    println!("Syncing repos");

    let cve_repo_path = Path::new(CVE_REPO_PATH);
    match cve_repo_path.try_exists() {
        Ok(true) => {
            checkout_repo_head(cve_repo_path).expect("Should be able to checkout CVE repo");
        }
        Ok(false) => {
            println!("Cloning CVE repo");
            let cve_repo_url = "https://git.kernel.org/pub/scm/linux/security/vulns.git";
            Repository::clone(cve_repo_url, cve_repo_path)
                .expect("Should be able to clone CVE repo");
        }
        Err(e) => {
            panic!("Unexpected failure: {}", e);
        }
    };

    let linux_repo_url = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
    let linux_repo_path = Path::new(&LINUX_REPO_PATH);
    match linux_repo_path.try_exists() {
        Ok(true) => {
            checkout_repo_head(linux_repo_path).expect("Should be able to checkout Linux repo")
        }
        Ok(false) => {
            println!(
                "Cloning Linux repo. (This will take a long time without printouts. Please wait.)"
            );
            Repository::clone(linux_repo_url, linux_repo_path)
                .expect("Should be able to clone Linux repo");
        }
        Err(e) => {
            panic!("Unexpected failure: {}", e);
        }
    }

    println!("Repos done syncing");
}

fn checkout_repo_head(path: &Path) -> Result<()> {
    let result = Command::new("git")
        .current_dir(path)
        .args(["clean", "-f", "-d", "-x"])
        .spawn()?
        .wait_with_output()?;

    if !result.status.success() {
        return Err(eyre!(
            "git clean -f -d -x failed with output: {}",
            String::from_utf8(result.stdout)?
        ));
    }

    let result = Command::new("git")
        .current_dir(path)
        .args(["reset", "--hard", "HEAD"])
        .spawn()?
        .wait_with_output()?;

    if !result.status.success() {
        return Err(eyre!(
            "git reset --hard HEAD failed with output: {}",
            String::from_utf8(result.stdout)?
        ));
    }

    let result = Command::new("git")
        .current_dir(path)
        .args(["checkout", "master"])
        .spawn()?
        .wait_with_output()?;

    if !result.status.success() {
        return Err(eyre!(
            "git checkout master failed with output: {}",
            String::from_utf8(result.stdout)?
        ));
    }

    let result = Command::new("git")
        .current_dir(path)
        .arg("pull")
        .spawn()?
        .wait_with_output()?;

    if !result.status.success() {
        return Err(eyre!(
            "git pull failed with output: {}",
            String::from_utf8(result.stdout)?
        ));
    }

    Ok(())
}

#[derive(Debug)]
struct KernelVersion {
    major: u8,
    minor: u8,
    patch: u16,
}

impl TryFrom<&str> for KernelVersion {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let split_value: Vec<&str> = value.split('.').collect();
        if split_value.len() < 2 {
            return Err(anyhow::anyhow!(
                "Kernel version must contain at least a major and minor"
            ));
        }

        let major = split_value[0];
        let minor = split_value[1];
        // Patch may or may not exist
        let patch = split_value.get(2);

        let major = major.parse::<u8>()?;
        let minor = minor.parse::<u8>()?;
        let patch = if patch.is_some() {
            patch.unwrap().parse::<u16>()?
        } else {
            0
        };

        Ok(KernelVersion {
            major,
            minor,
            patch,
        })
    }
}

/// An instance of a CVE which was introduced in a particular kernel version.
/// This CVE may or may not have been fixed in a future version. If it has,
/// then a fix should exist.
#[derive(Debug)]
struct CveInstance {
    introduced: KernelVersion,
    fixed: Option<KernelVersion>,
    fixed_commit_prefix: Option<String>,
    patch: Option<String>,
    affected_files: Option<Vec<String>>,
}

/// A particular CVE and all instances of it occuring within different versions of the kernel.
#[derive(Debug)]
struct Cve {
    name: String,
    severity: Option<f64>,
    attack_vector: Option<String>,
    attack_complexity: Option<String>,
    privileges_required: Option<String>,
    user_interaction: Option<String>,
    scope: Option<String>,
    confidentiality_impact: Option<String>,
    integrity_impact: Option<String>,
    availability_impact: Option<String>,
    description: Option<String>,
    instances: Vec<CveInstance>,
}

fn generate_patch(
    linux_repo: &Repository,
    fixed_commit_hash: &str,
) -> Result<Patch, anyhow::Error> {
    let fixed_commit = linux_repo.find_commit(Oid::from_str(fixed_commit_hash)?)?;
    let parent_commit = fixed_commit.parent(0)?;
    let diff = linux_repo.diff_tree_to_tree(
        Some(&parent_commit.tree()?),
        Some(&fixed_commit.tree()?),
        None,
    )?;

    let mut patch = Patch::default();
    for i in 0..diff.stats()?.files_changed() {
        let file_path = diff
            .get_delta(i)
            .expect("delta[i] should exist if files_changed() goes up to i")
            .old_file()
            .path();

        if let Some(file_path) = file_path {
            patch.affected_files.push(
                file_path
                    .to_str()
                    .expect("File path should be UTF-8 valid")
                    .to_string(),
            );
        }

        let file_patch = git2::Patch::from_diff(&diff, i)?;
        if let Some(mut file_patch) = file_patch {
            if let Ok(file_patch_buf) = file_patch.to_buf() {
                if let Some(file_patch_str) = file_patch_buf.as_str() {
                    patch.patch_file.push_str(file_patch_str);
                }
            }
        }
    }

    Ok(patch)
}

#[derive(Default)]
struct Patch {
    patch_file: String,
    affected_files: Vec<String>,
}

/// Fetches all new CVEs and patches since the commit specified by last_vulns_commit up until to_commit.
/// If last_vulns_commit is None, this will fetch all CVEs and patches.
fn fetch_cves(from_commit: Option<&str>) -> anyhow::Result<Vec<Cve>, anyhow::Error> {
    println!("Fetching CVEs");

    let mut cves: Vec<Cve> = Vec::new();
    let linux_repo = Repository::open(LINUX_REPO_PATH).expect("Linux repo should exist");
    let vulns_repo = Repository::open(CVE_REPO_PATH).expect("Vulns repo should exist");

    let vulns_initial_commit = "9bcaccade458ba4cc2e44e8a84b4be6fa36d46aa";
    let from_commit_id = git2::Oid::from_str(from_commit.unwrap_or(vulns_initial_commit))?;
    let to_commit_id = vulns_repo.revparse("HEAD")?.from().unwrap().id();

    let from_commit = vulns_repo.find_commit(from_commit_id)?;
    let to_commit = vulns_repo.find_commit(to_commit_id)?;

    // We only care about .dyad files regarding published CVEs
    let mut opts = git2::DiffOptions::new();
    opts.pathspec("cve/published/*/*.dyad");

    let diff = vulns_repo.diff_tree_to_tree(
        Some(&from_commit.tree()?),
        Some(&to_commit.tree()?),
        Some(&mut opts),
    )?;
    for delta in diff.deltas() {
        let dyad_relative_path = delta.new_file().path().unwrap().to_str().unwrap();
        let dyad_real_path = format!("{}/{}", CVE_REPO_PATH, dyad_relative_path);
        let dyad_real_path = Path::new(&dyad_real_path);

        if !dyad_real_path.exists() {
            // Just because a dyad is mentioned in the delta doesn't mean it was created: it could have been moved.
            continue;
        }

        if let Some(cve) = get_patch_commits_from_dyad(Path::new(&dyad_real_path), &linux_repo) {
            println!("Found new CVE: {}", &cve.name);
            cves.push(cve);
        }
    }
    println!("Done fetching CVEs");

    Ok(cves)
}

fn get_patch_commits_from_dyad(dyad_path: &Path, linux_repo: &Repository) -> Option<Cve> {
    let file = File::open(dyad_path).unwrap();
    let dyad = BufReader::new(file);

    let cve_name = dyad_path.file_stem()?.to_str()?;
    let mut cve = Cve {
        name: cve_name.to_string(),
        // NIST-specific fields to be added later
        severity: None,
        attack_vector: None,
        attack_complexity: None,
        privileges_required: None,
        user_interaction: None,
        scope: None,
        confidentiality_impact: None,
        integrity_impact: None,
        availability_impact: None,
        description: None,
        // End NIST-specific fields
        instances: Vec::new(),
    };

    for line in dyad.lines() {
        let line = line.unwrap();
        let trimmed_line = line.trim();

        if trimmed_line.contains("#") {
            // Dyad uses # for comment lines. Skip those.
            continue;
        }

        // Dyad is in the following format:
        // {introuced_ver}:{introduced_commit_hash}:{fixed_ver}:{fixed_commit_hash}
        //
        // If {introduced_ver} or {introduced_commit_hash} == 0, the issue was introduced before
        // the Linux stable Git repository history (version 2.6.12, commit 1da177e4c3f4).
        // If {fixed_ver} or {fixed_commit} == 0, there is no fix for that kernel version.
        let split_line: Vec<&str> = trimmed_line.split_terminator(':').collect();

        if split_line.len() < 4 {
            println!("Improperly formatted .dyad received for: {}", cve.name);
            continue;
        }

        let introduced_ver = if split_line[0] == "0" {
            "2.6.12"
        } else {
            split_line[0]
        };
        let fixed_ver = split_line[2];
        let fixed_commit_hash = split_line[3];
        let fixed_commit_prefix = if fixed_commit_hash.len() >= 12 {
            &fixed_commit_hash[..12]
        } else {
            "0"
        };

        let Ok(cve_introduced) = KernelVersion::try_from(introduced_ver) else {
            println!("Unsupported kernel version received: {}", introduced_ver);
            continue;
        };

        if fixed_commit_hash == "0" {
            cve.instances.push(CveInstance {
                introduced: cve_introduced,
                fixed: None,
                fixed_commit_prefix: None,
                patch: None,
                affected_files: None,
            });
            continue;
        }

        let Ok(fixed_ver) = KernelVersion::try_from(fixed_ver) else {
            println!("Unsupported kernel version received: {}", fixed_ver);
            continue;
        };

        let patch = generate_patch(linux_repo, fixed_commit_hash).unwrap();
        cve.instances.push(CveInstance {
            introduced: cve_introduced,
            fixed: Some(fixed_ver),
            fixed_commit_prefix: Some(fixed_commit_prefix.to_string()),
            patch: Some(patch.patch_file),
            affected_files: Some(patch.affected_files),
        });
    }

    Some(cve)
}

/// Fetches the metadata for the CVEs from the NIST API and adds it to the argument if it exists.
///
/// `full_fetch` should be `true` if this program's database is being fully initialized and `false` otherwise.
/// For speed purposes, this program does batch requests to the API when initializing its database and iteritive
/// requests when updating its database.
fn fetch_nist(cves: &mut Vec<Cve>, full_fetch: bool, api_key: Option<&str>) {
    println!("Fetching CVE severities from NIST.");

    if full_fetch {
        fetch_nist_batch(cves, api_key);
    } else {
        fetch_nist_iteritive(cves, api_key);
    }
}

/// Pulls the entire CVE database from NIST for initialization of this program's database.
fn fetch_nist_batch(cves: &mut Vec<Cve>, api_key: Option<&str>) {
    // Set window duration to >30s even though NIST suggests 30s as it will 403 if it's spot on.
    let mut rate_limiter = if api_key.is_some() {
        RateLimiter::new(50, Duration::from_secs(32))
    } else {
        RateLimiter::new(5, Duration::from_secs(32))
    };

    // NIST API has a maximum of 2000 results-per-page when pulling in batch.
    let results_per_page = 2000;
    let results_per_page_string = results_per_page.to_string();

    let mut vulnerabilities: HashMap<String, Vulnerability> = HashMap::new();

    // last_index will later become the `totalResults` field from the response.
    let mut last_index = 1;
    let mut current_index = 0;
    while current_index <= last_index {
        rate_limiter.limit();

        let response = ureq::get(NIST_API_URL)
            .query("resultsPerPage", results_per_page_string.as_str())
            .query("startIndex", current_index.to_string().as_str())
            .call();

        match response {
            Ok(response) => {
                let nist_response: Result<NistResponse, std::io::Error> = response.into_json();
                match nist_response {
                    Ok(nist_response) => {
                        last_index = nist_response.total_results;
                        for response_vuln in nist_response.vulnerabilities {
                            vulnerabilities.insert(response_vuln.cve.id.clone(), response_vuln);
                        }
                    }
                    Err(e) => {
                        eprintln!("Could not parse NIST API response: {}", &e);
                    }
                }
                // This print is after the match block as last_index will not be correct
                // until the first response.
                println!("Fetching CVE metadata: [{current_index}/{last_index}]");
            }
            Err(e) => {
                eprintln!("Bad response from NIST API: {}", &e);
                println!("Requesting index {} again.", current_index);
                // Try requesting this index again
                continue;
            }
        }

        current_index += results_per_page;
    }

    for cve in cves {
        if let Some(vulnerability) = vulnerabilities.get(&cve.name) {
            println!("Fetched new metadata for {}", &cve.name);
            update_cve_from_nist_vulnerability(cve, vulnerability);
        }
    }
}

/// Fetches NIST data by making individual requests to the NIST API.
fn fetch_nist_iteritive(cves: &mut [Cve], api_key: Option<&str>) {
    // Set window duration to >30s even though NIST suggests 30s as it will 403 if it's spot on.
    let mut rate_limiter = if api_key.is_some() {
        RateLimiter::new(50, Duration::from_secs(32))
    } else {
        RateLimiter::new(5, Duration::from_secs(32))
    };

    let mut index = 0;
    while index < cves.len() {
        // SAFETY: Use of [] addressing is safe as `cves` will never be resized.
        let cve = &mut cves[index];

        rate_limiter.limit();

        let response = ureq::get(NIST_API_URL).query("cveId", &cve.name).call();
        match response {
            Ok(response) => {
                let nist_response: Result<NistResponse, std::io::Error> = response.into_json();
                match nist_response {
                    Ok(nist_response) => {
                        if let Some(vulnerability) = nist_response.vulnerabilities.first() {
                            println!("Fetched new metadata for {}", &cve.name);
                            update_cve_from_nist_vulnerability(cve, vulnerability);
                        }
                    }
                    Err(e) => {
                        eprintln!("Could not parse NIST API response: {}", &e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Bad response from NIST API: {}", &e);
                println!("Requesting metadata for {} again.", &cve.name);
                continue;
            }
        }

        index += 1;
    }
}

/// Update a single CVE from a single NIST vulnerability.
fn update_cve_from_nist_vulnerability(cve: &mut Cve, vulnerability: &Vulnerability) {
    // There should only be <=1 english description, but it'll be deserialized into a vec
    let english_description: Vec<&nist_api_types::Description> = vulnerability
        .cve
        .descriptions
        .iter()
        .filter(|desc| desc.lang == "en")
        .collect();
    if let Some(description) = english_description.first() {
        cve.description = Some(description.value.clone());
    }

    if let Some(metric) = &vulnerability.cve.metrics.cvss_metric_v31 {
        if let Some(cvss_metric_v31) = metric.first() {
            let cvss_data = cvss_metric_v31.cvss_data.clone();
            cve.severity = Some(cvss_data.base_score);
            cve.attack_vector = Some(cvss_data.attack_vector);
            cve.attack_complexity = Some(cvss_data.attack_complexity);
            cve.privileges_required = Some(cvss_data.privileges_required);
            cve.user_interaction = Some(cvss_data.user_interaction);
            cve.scope = Some(cvss_data.scope);
            cve.confidentiality_impact = Some(cvss_data.confidentiality_impact);
            cve.integrity_impact = Some(cvss_data.integrity_impact);
            cve.availability_impact = Some(cvss_data.availability_impact);
        }
    } else {
        // If vulnerabilities/cve/metrics/cvss_metric_v31 is empty, this CVE has not yet been rated.
        // Ignore this one.
    }
}
