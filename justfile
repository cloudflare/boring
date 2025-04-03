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
	cargo test --features rpk
	cargo test --features pq-experimental
	cargo test --features underscore-wildcards
	cargo test --features pq-experimental,rpk
	cargo test --features kx-safe-default,pq-experimental
	cargo test --features pq-experimental,underscore-wildcards
	cargo test --features rpk,underscore-wildcards
	cargo test --features pq-experimental,rpk,underscore-wildcards

qa: lint check clippy doc test dry-publish

publish:
	bash scripts/publish.sh
