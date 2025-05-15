fmt:
	cargo fmt --all

sort:
	cargo sort --workspace --grouped

lint: fmt sort

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets

dry-publish:
	cargo publish --dry-run -p rama-boring-sys

doc:
	RUSTDOCFLAGS="-D rustdoc::broken-intra-doc-links" cargo doc  --no-deps

test:
	cargo test
	cargo test --features underscore-wildcards

qa: lint check clippy doc test dry-publish

publish:
	bash scripts/publish.sh
