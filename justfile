fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc  --no-deps

test:
	cargo test

qa: lint check clippy doc test

publish:
	bash scripts/publish.sh
