//! Zone-transfer discovery against a nameserver on the loopback interface.

mod common;

use common::*;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zoneblick::discover::axfr_from;

/// Serve one TCP query with the messages `answer` builds from it.
async fn serve_once(
    answer: impl Fn(&Message) -> Vec<Message> + Send + 'static,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.unwrap();
        let query = Message::from_vec(&buf).unwrap();
        for msg in answer(&query) {
            let wire = msg.to_vec().unwrap();
            stream
                .write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&wire).await.unwrap();
        }
    });
    addr
}

fn response(query: &Message, rcode: ResponseCode) -> Message {
    let mut msg = Message::query();
    msg.metadata.id = query.metadata.id;
    msg.metadata.message_type = MessageType::Response;
    msg.metadata.response_code = rcode;
    msg
}

#[tokio::test]
async fn a_transfer_gives_the_names_in_the_zone() {
    let zone = "good.example.";
    let addr = serve_once(move |query| {
        // Two messages, as a large zone would need.
        let mut first = response(query, ResponseCode::NoError);
        first.answers.extend([
            soa(zone, 7),
            ns(zone, "ns1.good.example."),
            addr("www.good.example.", "192.0.2.10"),
            cname("shop.good.example.", "shops.host.example."),
        ]);
        let mut second = response(query, ResponseCode::NoError);
        second.answers.extend([
            txt(zone, "v=spf1 -all"),
            addr("*.wild.good.example.", "192.0.2.11"),
            addr("mail.good.example.", "2001:db8::25"),
            soa(zone, 7),
        ]);
        vec![first, second]
    })
    .await;
    assert_eq!(
        axfr_from(zone, addr).await.unwrap(),
        [
            "mail.good.example.",
            "shop.good.example.",
            "www.good.example."
        ]
    );
}

#[tokio::test]
async fn a_refused_transfer_is_an_error() {
    let addr = serve_once(|query| vec![response(query, ResponseCode::Refused)]).await;
    let err = axfr_from("good.example.", addr).await.unwrap_err();
    assert!(err.contains("transfer refused (REFUSED)"), "{err}");
}
