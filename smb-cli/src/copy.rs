use crate::{path::*, Cli};
use clap::Parser;
use maybe_async::*;
use smb::resource::*;
#[cfg(not(feature = "single_threaded"))]
use smb::sync_helpers::*;
use std::error::Error;
#[cfg(not(feature = "async"))]
use std::fs;
#[cfg(feature = "multi_threaded")]
use std::io::Write;
#[cfg(not(feature = "single_threaded"))]
use std::sync::Arc;

#[cfg(feature = "async")]
use tokio::{fs, io::AsyncWriteExt};

#[derive(Parser, Debug)]
pub struct CopyCmd {
    pub from: Path,
    pub to: Path,
}

#[cfg(feature = "single_threaded")]
fn do_copy(from: File, mut to: fs::File) -> Result<(), smb::Error> {
    use std::io::{copy, BufReader};

    let mut buffered_reader = BufReader::with_capacity(32768, from);
    copy(&mut buffered_reader, &mut to)?;

    Ok(())
}

#[cfg(not(feature = "single_threaded"))]
const WORKERS: usize = 16;
#[cfg(not(feature = "single_threaded"))]
const CHUNK_SIZE: usize = 2usize.pow(16);

#[cfg(not(feature = "single_threaded"))]
#[maybe_async]
async fn do_copy_task(
    from: Arc<File>,
    to: Arc<Mutex<fs::File>>,
    curr_chunk: Arc<Mutex<usize>>,
) -> Result<(), smb::Error> {
    let file_size = from.end_of_file() as usize;
    let last_chunk = file_size / CHUNK_SIZE;
    let mut chunk = vec![0u8; CHUNK_SIZE as usize];
    loop {
        // 1. Get next chunk index & size
        let (idx, size) = {
            let mut curr_chunk = curr_chunk.lock().await?;
            let chunk_index = *curr_chunk;
            *curr_chunk += 1;

            if chunk_index > last_chunk {
                break;
            }
            if chunk_index == last_chunk {
                let last_chunk_size = file_size % CHUNK_SIZE;
                (chunk_index, last_chunk_size)
            } else {
                (chunk_index, CHUNK_SIZE)
            }
        };
        // 2. Read chunk from remote
        from.read_block(&mut chunk[..size], (idx * CHUNK_SIZE) as u64, false)
            .await?;
        // 3. Write chunk to destination
        {
            to.lock().await?.write_all(&chunk[..size]).await?;
        }
    }
    Ok(())
}

#[cfg(any(feature = "async"))]
async fn do_copy(from: File, to: fs::File) -> Result<(), smb::Error> {
    use tokio::task::JoinSet;

    // Create a queue of chunks to be written
    let curr_chunk = Arc::new(Mutex::new(0));
    let from = Arc::new(from);
    let to = Arc::new(Mutex::new(to));

    let mut handles = JoinSet::new();
    for _ in 0..WORKERS {
        let curr_chunk = curr_chunk.clone();
        let from = from.clone();
        let to = to.clone();
        handles.spawn(async move {
            do_copy_task(from.clone(), to, curr_chunk).await.unwrap();
        });
    }

    handles.join_all().await;

    Ok(())
}

#[cfg(feature = "multi_threaded")]
fn do_copy(from: File, to: fs::File) -> Result<(), smb::Error> {
    // Create a queue of chunks to be written
    let curr_chunk = Arc::new(Mutex::new(0));
    let from = Arc::new(from);
    let to = Arc::new(Mutex::new(to));

    let mut handles = Vec::new();
    for _ in 0..WORKERS {
        let curr_chunk = curr_chunk.clone();
        let from = from.clone();
        let to = to.clone();
        let handle = std::thread::spawn(move || do_copy_task(from.clone(), to, curr_chunk));
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap()?;
    }

    Ok(())
}

#[maybe_async]
pub async fn copy(cmd: &CopyCmd, cli: &Cli) -> Result<(), Box<dyn Error>> {
    {
        let (from, client) = match &cmd.from {
            Path::Local(_) => panic!("Local to local copy not supported"),
            Path::Remote(unc_path) => {
                let (client, _session, _tree, mut resource) =
                    unc_path.connect_and_open(cli).await?;
                (
                    resource
                        .take()
                        .ok_or("Source file not found")?
                        .unwrap_file(),
                    client,
                )
            }
        };

        let to: fs::File = match &cmd.to {
            Path::Local(path_buf) => fs::File::create(path_buf).await?,
            Path::Remote(_) => panic!("Remote to remote copy not supported"),
        };

        do_copy(from, to).await?;

        client
    }
    .close()
    .await?;

    Ok(())
}
