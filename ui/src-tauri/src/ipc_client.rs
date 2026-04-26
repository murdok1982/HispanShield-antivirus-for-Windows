use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};

pub struct IpcClient {
    pipe_name: String,
    auth_token: String,
}

impl IpcClient {
    pub fn new(pipe_name: &str, auth_token: &str) -> Self {
        Self {
            pipe_name: pipe_name.to_string(),
            auth_token: auth_token.to_string(),
        }
    }

    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let pipe_name = self.pipe_name.clone();
        let auth = self.auth_token.clone();
        let method = method.to_string();

        tokio::task::spawn_blocking(move || -> Result<Value> {
            call_pipe(&pipe_name, &auth, &method, params)
        })
        .await
        .context("IPC task panicked")?
    }
}

fn call_pipe(pipe_name: &str, auth: &str, method: &str, params: Option<Value>) -> Result<Value> {
    use std::fs::OpenOptions;
    use std::time::Duration;

    // Retry up to 3 times in case pipe is busy
    let mut last_err = None;
    for attempt in 0..3 {
        match try_call_pipe(pipe_name, auth, method, &params) {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("IPC call failed")))
}

fn try_call_pipe(
    pipe_name: &str,
    auth: &str,
    method: &str,
    params: &Option<Value>,
) -> Result<Value> {
    use std::fs::OpenOptions;

    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)
        .context("Cannot connect to HispanShield agent pipe. Is the service running?")?;

    let request = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": auth
    });

    let mut req_bytes = serde_json::to_vec(&request)?;
    req_bytes.push(b'\n');
    pipe.write_all(&req_bytes)?;
    pipe.flush()?;

    let mut reader = BufReader::new(&pipe);
    let mut response = String::new();
    reader.read_line(&mut response)?;

    let resp: Value = serde_json::from_str(response.trim())
        .context("Failed to parse IPC response")?;

    if let Some(error) = resp.get("error") {
        return Err(anyhow::anyhow!("Agent error: {}", error));
    }

    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}
