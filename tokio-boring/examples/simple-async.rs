use boring::ssl;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    let (tcp_stream, _addr) = listener.accept().await?;

    let server = ssl::SslMethod::tls_server();
    let mut ssl_builder = boring::ssl::SslAcceptor::mozilla_modern(server)?;
    ssl_builder.set_default_verify_paths()?;
    ssl_builder.set_verify(ssl::SslVerifyMode::PEER);
    let acceptor = ssl_builder.build();
    let _ssl_stream = tokio_boring::accept(&acceptor, tcp_stream).await?;
    Ok(())
}
