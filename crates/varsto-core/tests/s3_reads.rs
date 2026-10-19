//! S3 reads against servers that answer in the ways real ones do: a body of
//! exactly the allowed size, and Range requests answered with `200`.

use std::sync::Arc;
use std::thread::JoinHandle;

use varsto_core::fsck3::{probe_len, LenProbe};
use varsto_core::s3::{S3Config, S3Storage};
use varsto_core::storage::Storage;

/// How the fake server answers a `Range` request.
#[derive(Clone, Copy, Debug)]
enum RangeAnswer {
    /// `206` with `Content-Range` (AWS, MinIO).
    Partial,
    /// `200` with `Content-Range` and only the asked bytes, clipped at the
    /// object's end (`rclone serve s3`).
    OkWithContentRange,
    /// `200` with the whole object (a server that ignores `Range`).
    WholeObject,
}

fn parse_range(h: &str, total: u64) -> Option<(u64, u64)> {
    let spec = h.trim().strip_prefix("bytes=")?;
    let (a, z) = spec.split_once('-')?;
    let a: u64 = a.parse().ok()?;
    let z: u64 = z.parse().ok()?;
    if a >= total {
        return None;
    }
    Some((a, z.min(total - 1)))
}

/// A server holding one object, answering every GET with it.
fn serve(object: Vec<u8>, how: RangeAnswer, requests: usize) -> (u16, JoinHandle<()>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let object = Arc::new(object);
    let th = std::thread::spawn(move || {
        for _ in 0..requests {
            let req = server.recv().unwrap();
            let range = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("range"))
                .map(|h| h.value.as_str().to_string());
            let total = object.len() as u64;
            let resp = match range {
                None => tiny_http::Response::from_data(object.to_vec()),
                Some(r) => match (how, parse_range(&r, total)) {
                    (RangeAnswer::WholeObject, _) => {
                        tiny_http::Response::from_data(object.to_vec())
                    }
                    (_, None) => tiny_http::Response::from_data(Vec::new()).with_status_code(416),
                    (how, Some((a, z))) => {
                        let part = object[a as usize..=z as usize].to_vec();
                        let header = tiny_http::Header::from_bytes(
                            "Content-Range",
                            format!("bytes {a}-{z}/{total}"),
                        )
                        .unwrap();
                        let code = match how {
                            RangeAnswer::Partial => 206,
                            _ => 200,
                        };
                        tiny_http::Response::from_data(part)
                            .with_status_code(code)
                            .with_header(header)
                    }
                },
            };
            req.respond(resp).unwrap();
        }
    });
    (port, th)
}

fn storage_for(port: u16) -> S3Storage {
    S3Storage::new(S3Config {
        name: "test".into(),
        endpoint: format!("http://127.0.0.1:{port}"),
        region: "us-east-1".into(),
        bucket: "b".into(),
        prefix: String::new(),
        access_key_id: "k".into(),
        secret_access_key: "s".into(),
        path_style: true,
        storage_class: None,
        allow_insecure_http: false,
        conditional_writes: None,
    })
    .unwrap()
}

/// A pack is exactly its class size, and GC reads it with that size as the
/// cap: a body of exactly the cap must be accepted, one byte more refused.
#[test]
fn a_body_of_exactly_the_cap_is_read() {
    let cap = 1u64 << 20;
    let object: Vec<u8> = (0..cap as u32).map(|i| (i % 251) as u8).collect();
    let (port, th) = serve(object.clone(), RangeAnswer::Partial, 1);
    let got = storage_for(port).get_bounded("packs/ab/cd", cap).unwrap();
    assert_eq!(got.as_deref(), Some(&object[..]));
    th.join().unwrap();

    let mut longer = object;
    longer.push(1);
    let (port, th) = serve(longer, RangeAnswer::Partial, 1);
    assert!(storage_for(port).get_bounded("packs/ab/cd", cap).is_err());
    th.join().unwrap();
}

/// Every way a server answers a Range request gives the asked bytes, a range
/// clipped at the end gives the bytes there, and a pack of its class length
/// probes as exact (fsck called every pack on `rclone serve s3` shorter).
#[test]
fn range_reads_work_whatever_the_server_answers() {
    let class = 64 * 1024u64;
    let object: Vec<u8> = (0..class as u32).map(|i| (i % 253) as u8).collect();
    for how in [
        RangeAnswer::Partial,
        RangeAnswer::OkWithContentRange,
        RangeAnswer::WholeObject,
    ] {
        let (port, th) = serve(object.clone(), how, 6);
        let s = storage_for(port);
        let key = "packs/ab/cdef";
        assert_eq!(
            s.get_range(key, 0, 10).unwrap().unwrap(),
            &object[..10],
            "{how:?}"
        );
        assert_eq!(
            s.get_range(key, 1000, 500).unwrap().unwrap(),
            &object[1000..1500],
            "{how:?}"
        );
        // Clipped at the end of the object.
        assert_eq!(
            s.get_range(key, class - 3, 10).unwrap().unwrap(),
            &object[class as usize - 3..],
            "{how:?}"
        );
        // Past the end: empty, not an error.
        assert_eq!(
            s.get_range(key, class + 5, 2).unwrap().unwrap(),
            Vec::<u8>::new(),
            "{how:?}"
        );
        let pack = [0xabu8; 32];
        assert_eq!(
            probe_len(&s, &pack, class).unwrap(),
            LenProbe::Exact,
            "{how:?}"
        );
        assert_eq!(
            probe_len(&s, &pack, class / 2).unwrap(),
            LenProbe::Longer,
            "{how:?}"
        );
        th.join().unwrap();
    }
}
