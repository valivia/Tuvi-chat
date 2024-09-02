use dashmap::DashMap as HashMap;
use rocket::fs::NamedFile;
use rocket::futures::SinkExt;
use rocket::futures::StreamExt;
use crate::fs::relative;
use rocket::*;
use rocket_ws as ws;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::select;

mod msac;

type Channels = Arc<HashMap<String, msac::Channel>>;

#[get("/<path..>")]
pub async fn serve(path: PathBuf) -> Option<NamedFile> {
    let mut path = Path::new(relative!("../web/build")).join(path);
    if path.is_dir() {
        path.push("index.html");
    }

    NamedFile::open(path).await.ok()
}

#[get("/echo/<room>")]
async fn echo_socket(ws: ws::WebSocket, room: String, channels: &State<Channels>) -> ws::Channel {
    let (tx, mut rx) = {
        let channel = channels
            .entry(room.clone())
            .or_insert_with(msac::Channel::new);
        channel.add().await
    };
    ws.channel(move |mut stream| {
        Box::pin(async move {
            loop {
                select! {
                    // Receive message from user
                    message = stream.next() => {
                        if let Some(message) = message {
                            let message = message.unwrap();
                            // check, if the message is a string
                            if let rocket_ws::Message::Text(message) = message {
                                // send the message to all connected clients
                                tx.send(message.to_string()).await.unwrap();
                            }
                            // stream.send(rocket_ws::Message::Text(message.to_string())).await.unwrap();
                        } else {
                            break;
                        }
                    },
                    // Receive message from room
                    message = rx.recv() => {
                        if let Some(message) = message {
                            if let Err(_) = stream.send(rocket_ws::Message::Text(message)).await {
                                break;
                            }
                        }
                    }
                }
            }

            // remove the connection from the channel
            let channel = channels.get_mut(&room).unwrap();
            if channel.remove().await {
                println!("removing channel for room {}", room);
                channels.remove(&room);
            }

            Ok(())
        })
    })
}

#[launch]
async fn rocket() -> _ {
    let rocket = rocket::build().mount("/", rocket::routes![echo_socket, serve]);

    // manage a mpmc channel for strings
    // let channel = msac::Channel::new();
    let channels: Channels = Arc::new(HashMap::new());
    rocket.manage(channels)
}
