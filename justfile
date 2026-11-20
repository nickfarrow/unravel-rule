# Build the browser side to WASM.
wasm:
    cd web && wasm-pack build --target web --out-dir pkg --no-typescript
    python3 web/bundle.py

# Build everything and run the regtest demo at http://127.0.0.1:8322
demo: wasm
    cargo run -p unravel-server

# Unit tests, then end-to-end tests on a regtest Bitcoin Core that the bitcoind crate downloads.
test:
    cargo test --workspace

# Run on Bitcoin mainnet, reading the chain from Blockstream's public Electrum server. Real money: small amounts.
mainnet: wasm
    UNRAVEL_NETWORK=bitcoin cargo run -p unravel-server

# Spend a hop address through its safety net, offline, with your emergency kit and the seed of your bc1p address's wallet.
[no-cd]
rescue kit hop *exchanges:
    cargo run -q --locked --release --manifest-path "{{justfile_directory()}}/Cargo.toml" -p unravel-rescue -- "{{kit}}" "{{hop}}" {{exchanges}}
