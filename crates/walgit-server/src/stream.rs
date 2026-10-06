//! Streaming bridges between axum/hyper bodies and tokio `AsyncRead`/`AsyncWrite`.
//!
//! * Incoming request body -> `AsyncRead` (with optional gzip inflate).
//! * Outgoing response: the write half of a tokio duplex pipe rendered as a
//!   hyper `Body` via `Body::from_stream`, so git pkt-line / pack output streams
//!   straight to the client with no full buffering.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use bytes::Bytes;
use futures::stream::{Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tokio_util::io::{ReaderStream, StreamReader};

/// Convert an axum request body into an `AsyncRead`. Map errors to `io::Error`.
pub fn body_to_async_read(body: Body) -> impl AsyncRead + Unpin + Send {
    let stream = body
        .into_data_stream()
        .map(|res| res.map_err(|e| io::Error::other(e.to_string())));
    StreamReader::new(stream)
}

/// Wrap an `AsyncRead` in gzip decompression when `content_encoding` is `gzip`.
/// Returns the original reader otherwise. The gzip decoder requires `AsyncBufRead`,
/// so the reader is wrapped in a `BufReader`.
pub fn maybe_gunzip<R: AsyncRead + Unpin + Send + 'static>(
    content_encoding: Option<&str>,
    reader: R,
) -> Box<dyn AsyncRead + Unpin + Send> {
    match content_encoding
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("gzip") => Box::new(async_compression::tokio::bufread::GzipDecoder::new(
            tokio::io::BufReader::new(reader),
        )),
        _ => Box::new(reader),
    }
}

/// Convert an `AsyncRead` into an axum `Body` (streamed, chunked).
pub fn body_from_async_read<R: AsyncRead + Unpin + Send + 'static>(reader: R) -> Body {
    Body::from_stream(ReaderStream::new(reader))
}

/// A duplex pipe: write on the returned `DuplexStream` (impl `AsyncWrite`),
/// read the resulting `Body` on the other side. Use when an API hands us an
/// `AsyncWrite` to fill (e.g. `LocalRepo::upload_pack`). Drop the writer to
/// signal EOF to the reader.
pub fn write_body_pipe(buf: usize) -> (tokio::io::DuplexStream, Body) {
    let (a, b) = tokio::io::duplex(buf);
    (a, Body::from_stream(ReaderStream::new(b)))
}

/// A simple `AsyncWrite` that collects bytes into a `Vec<u8>`. Used to render
/// small pkt-line responses (report-status, ls-refs) into a buffer.
pub struct VecWriter(pub Vec<u8>);

impl Default for VecWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl VecWriter {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsyncWrite for VecWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.get_mut().0.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// An `AsyncRead` that fails once more than its limit has been read. The limit is shared,
/// so a caller can raise it between the phases of one body (push commands, then the pack).
pub struct LimitedReader<R> {
    inner: R,
    read: u64,
    limit: Arc<AtomicU64>,
    what: &'static str,
}

impl<R> LimitedReader<R> {
    /// Read at most `limit` bytes of `inner`; `what` names the body in the error.
    pub fn new(inner: R, limit: u64, what: &'static str) -> Self {
        LimitedReader {
            inner,
            read: 0,
            limit: Arc::new(AtomicU64::new(limit)),
            what,
        }
    }

    /// The limit, to change while the body is read.
    pub fn limit(&self) -> Arc<AtomicU64> {
        self.limit.clone()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for LimitedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            this.read += (buf.filled().len() - before) as u64;
            let limit = this.limit.load(Ordering::Relaxed);
            if this.read > limit {
                // A failed read must leave the buffer as it found it.
                buf.set_filled(before);
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} over the {limit} byte limit", this.what),
                )));
            }
        }
        polled
    }
}

/// A request body held to a minimum pace: it ends with an error when nothing arrives for
/// `idle`, or when less than `min_rate` bytes per second arrived over a `window`. A client
/// trickling a body (or never finishing it) would otherwise hold its request slot, and
/// the handler waiting on it, for as long as the connection stays open.
pub struct PacedBody<S> {
    inner: S,
    idle: Duration,
    min_rate: u64,
    window: Duration,
    deadline: Pin<Box<Sleep>>,
    window_start: Option<Instant>,
    window_bytes: u64,
}

impl<S> PacedBody<S> {
    pub fn new(inner: S, idle: Duration, min_rate: u64, window: Duration) -> Self {
        PacedBody {
            inner,
            idle,
            min_rate,
            window,
            deadline: Box::pin(tokio::time::sleep(idle)),
            window_start: None,
            window_bytes: 0,
        }
    }
}

impl<S, E> Stream for PacedBody<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<axum::BoxError>,
{
    type Item = Result<Bytes, axum::BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let now = Instant::now();
        // The clock starts when the handler first reads the body: work before that (a
        // repository sync while the client waits on `100-continue`) is not the client's.
        if this.window_start.is_none() {
            this.deadline.as_mut().reset(now + this.idle);
        }
        let start = *this.window_start.get_or_insert(now);
        match this.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.deadline.as_mut().reset(now + this.idle);
                this.window_bytes += chunk.len() as u64;
                let elapsed = now.saturating_duration_since(start);
                if elapsed >= this.window {
                    let wanted = u128::from(this.min_rate) * elapsed.as_millis() / 1000;
                    if u128::from(this.window_bytes) < wanted {
                        return Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "request body sent too slowly",
                        )
                        .into())));
                    }
                    this.window_start = Some(now);
                    this.window_bytes = 0;
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                if this.deadline.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "request body stalled",
                    )
                    .into())));
                }
                Poll::Pending
            }
        }
    }
}

/// Middleware: every request body is read through [`PacedBody`].
pub async fn pace_request_body(
    axum::extract::State(st): axum::extract::State<Arc<crate::AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let server = &st.cfg.server;
    let (parts, body) = req.into_parts();
    let paced = PacedBody::new(
        body.into_data_stream(),
        server.body_idle_timeout,
        server.min_body_bytes_per_second.as_u64(),
        server.body_rate_window,
    );
    next.run(axum::extract::Request::from_parts(
        parts,
        Body::from_stream(paced),
    ))
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunks(
        size: usize,
        every: Duration,
        count: usize,
    ) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
        Box::pin(futures::stream::iter(0..count).then(move |_| async move {
            tokio::time::sleep(every).await;
            Ok(Bytes::from(vec![0u8; size]))
        }))
    }

    async fn drain<S: Stream<Item = Result<Bytes, axum::BoxError>> + Unpin>(
        mut body: S,
    ) -> (u64, Option<String>) {
        let mut got = 0;
        while let Some(item) = body.next().await {
            match item {
                Ok(chunk) => got += chunk.len() as u64,
                Err(e) => return (got, Some(e.to_string())),
            }
        }
        (got, None)
    }

    #[tokio::test]
    async fn a_body_at_pace_arrives_whole() {
        let body = PacedBody::new(
            chunks(1000, Duration::from_millis(10), 30),
            Duration::from_millis(200),
            10_000,
            Duration::from_millis(100),
        );
        assert_eq!(drain(body).await, (30_000, None));
    }

    #[tokio::test]
    async fn a_body_that_stops_sending_is_cut() {
        let inner = chunks(10, Duration::ZERO, 1).chain(futures::stream::pending());
        let body = PacedBody::new(inner, Duration::from_millis(100), 1, Duration::from_mins(1));
        let (got, err) = drain(body).await;
        assert_eq!(got, 10);
        assert_eq!(err.as_deref(), Some("request body stalled"));
    }

    #[tokio::test]
    async fn a_trickled_body_is_cut() {
        let body = PacedBody::new(
            chunks(10, Duration::from_millis(20), 100),
            Duration::from_secs(5),
            10_000,
            Duration::from_millis(200),
        );
        let (got, err) = drain(body).await;
        assert!(got < 1000, "{got}");
        assert_eq!(err.as_deref(), Some("request body sent too slowly"));
    }

    #[tokio::test]
    async fn the_clock_starts_at_the_first_read() {
        let body = PacedBody::new(
            chunks(10, Duration::ZERO, 1),
            Duration::from_millis(50),
            1,
            Duration::from_mins(1),
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(drain(body).await, (10, None));
    }

    #[tokio::test]
    async fn a_limited_reader_fails_past_its_limit_until_raised() {
        use tokio::io::AsyncReadExt;
        let mut reader = LimitedReader::new(&[7u8; 100][..], 10, "commands");
        let mut buf = vec![0u8; 100];
        let err = reader.read_to_end(&mut buf).await.unwrap_err();
        assert!(
            err.to_string().contains("commands over the 10 byte limit"),
            "{err}"
        );
        let mut reader = LimitedReader::new(&[7u8; 100][..], 10, "commands");
        reader.limit().store(u64::MAX, Ordering::Relaxed);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out.len(), 100);
    }
}
