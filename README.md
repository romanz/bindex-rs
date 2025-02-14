# Bitcoin indexing library in Rust

[![CI](https://github.com/romanz/bindex/actions/workflows/rust.yml/badge.svg)](https://github.com/romanz/bindex/actions)
[![crates.io](https://img.shields.io/crates/v/bindex.svg)](https://crates.io/crates/bindex)

## Requirements

Currently, building an address index and querying it requires the following Bitcoin Core branch:

https://github.com/bitcoin/bitcoin/compare/master...romanz:bitcoin:bindex

## Usage

```
$ ~/src/bindex/run.sh 1B89jkAQwfvZFJsKphKC1hnfRxRM1DCPL7
+ export RUST_LOG=info
+ RUST_LOG=info
+ cargo +stable build --release --all
    Finished `release` profile [optimized] target(s) in 0.05s
+ target/release/bindex bitcoin 1B89jkAQwfvZFJsKphKC1hnfRxRM1DCPL7
[2025-02-13T18:38:58.365512Z INFO  bindex::db] CF headers: 3195 files, 72.861596 MBs
[2025-02-13T18:38:58.366097Z INFO  bindex::db] CF script_hash: 597 files, 39318.572647 MBs
[2025-02-13T18:38:58.900237Z INFO  bindex::chain] loaded 883613 headers
[2025-02-13T18:38:58.919465Z INFO  bindex::db] started auto compactions
[2025-02-13T18:38:58.924350Z INFO  bindex] 1 address history: 20 txs (4.86775ms)
[2025-02-13T18:38:58.932546Z INFO  bindex] fetched 20 txs, 0.792 MB, balance: 0 BTC, UTXOs: 0 (8.180709ms)
╭──────────────────────────────────────────────────────────────────┬─────────────────────────┬────────┬────────┬─────────────┬────────────┬───────┬───────╮
│ txid                                                             │ time                    │ height │ offset │ delta       │ balance    │ ms    │ bytes │
├──────────────────────────────────────────────────────────────────┼─────────────────────────┼────────┼────────┼─────────────┼────────────┼───────┼───────┤
│ 593e32eaa3b5f62822874a6db75575b8ad774f76473e80597f9345be8a34b3c8 │ 2024-02-12 04:40:19 UTC │ 830075 │    296 │ -0.00220000 │ 0.00000000 │ 0.657 │ 99998 │
│ 6a6905626015985a6dbd400ca319541fb482163b1e31349b238c1c2ec7137102 │ 2024-02-12 04:38:40 UTC │ 830074 │   1909 │ -0.00080000 │ 0.00220000 │ 0.585 │ 89999 │
│ e77ec98e70320e5a91e1a4e34abbe10afd6458286121b05bd92b8a2c5c5781cb │ 2024-02-11 03:00:37 UTC │ 829910 │   1381 │ -0.00026196 │ 0.00300000 │ 0.644 │ 98527 │
│ b2f92e6bf33de2dfd0d1454c091ef51bf46f6c76d14c2bfdce50641ab22faf67 │ 2023-12-24 12:04:52 UTC │ 822720 │    683 │ +0.00026196 │ 0.00326196 │ 0.188 │   290 │
│ fa19391d8ddd0bcf2c841ab451e188eb6df6afb6dde0bb95879880b71a7e4436 │ 2023-11-06 08:04:36 UTC │ 815553 │    182 │ +0.00220000 │ 0.00300000 │ 0.239 │   225 │
│ 0fc6ddc3da0c50942d688679a54bc27afa62e0b9e2496b2d224adeef07ee6669 │ 2023-10-04 15:08:40 UTC │ 810620 │   2044 │ +0.00080000 │ 0.00080000 │ 0.199 │   375 │
│ 29c391b673ea90b3fc29b91e91d1b4d56e2d7e33f0c7906eff8c1f355ba13b43 │ 2023-09-28 12:33:28 UTC │ 809729 │   1377 │ -0.00490073 │ 0.00000000 │ 0.616 │ 99849 │
│ 82be5ccf6b9b9ab0c23f8944ae4bf02873851902076c69c2d02ad7c01766cb59 │ 2023-09-27 11:53:14 UTC │ 809576 │    912 │ -0.00520000 │ 0.00490073 │ 0.761 │ 99999 │
│ 07521d70965a816c4db0d5d62b184e948915c68ee3d67d892d0de54d3cda03de │ 2023-09-19 08:14:03 UTC │ 808407 │    335 │ +0.00520000 │ 0.01010073 │ 0.198 │   225 │
│ bb729494854104c7d90fe310fe92cb2638cbf716c26bc47cae356825e1f59d78 │ 2023-08-30 21:20:49 UTC │ 805496 │   2938 │ +0.00183107 │ 0.00490073 │ 0.194 │   226 │
│ 4664dc0c6d4680c10a74d6e638d60de3acf27aac8de1f6dde1abfd6f297765c8 │ 2023-08-11 08:43:06 UTC │ 802637 │   2241 │ +0.00146956 │ 0.00306966 │ 0.190 │   195 │
│ 4be362dddbccd711c3c75c2ec1650bbec503ec0ebcdef73b3f6d9ee47eb8a6ba │ 2023-07-24 03:17:09 UTC │ 800000 │     24 │ +0.00160010 │ 0.00160010 │ 0.193 │   225 │
│ f32e7a50299ef85ca3e58b92692ffd2d1a2a7563bc0af0dcebf983d7282d5521 │ 2023-07-07 15:58:52 UTC │ 797613 │   2350 │ -0.00120000 │ 0.00000000 │ 0.596 │ 99410 │
│ 807d2c7d9ca8040f2637c1dbef5118349068e5a3fee102bf2c33496d6a8d100c │ 2023-07-05 13:28:50 UTC │ 797301 │     24 │ +0.00120000 │ 0.00120000 │ 0.206 │  1499 │
│ 315c3b004674b5b39d397edd67ee7ed7a0c6c6fa21852c1d3400e00da2840006 │ 2023-07-02 04:47:37 UTC │ 796796 │   2763 │ -0.00190000 │ 0.00000000 │ 0.587 │ 99999 │
│ 3d8cc06b0ffb50734f056ba63d6ccbc30e3556da6a1e9ce088d4e14e0bad235e │ 2023-06-18 04:58:35 UTC │ 794844 │    105 │ +0.00190000 │ 0.00190000 │ 0.280 │   225 │
│ 4ed70fcb07ed832d77d3b8aecf1ace5d14b23475cf0cbcd7352c4d86ecc29e95 │ 2023-06-08 12:14:25 UTC │ 793394 │   1979 │ -0.00795483 │ 0.00000000 │ 0.633 │ 99408 │
│ a33e9a426616cb3d2b5342351a11ac27cebf2e63902f89a38d2fd2c91314b40e │ 2023-06-01 10:28:30 UTC │ 792363 │    716 │ +0.00120000 │ 0.00795483 │ 0.214 │   375 │
│ 0d4a35ea84217e402d4ad61346b61643fe4f75dfc074c42e03eccd118d5a0a73 │ 2023-05-19 15:28:39 UTC │ 790477 │   1622 │ +0.00115483 │ 0.00675483 │ 0.242 │   225 │
│ d7e76d1ad6d2072452df36b699c14615c1ee7f8c42fb8742970501414ac83815 │ 2023-05-06 20:56:44 UTC │ 788554 │   2674 │ +0.00560000 │ 0.00560000 │ 0.431 │   256 │
╰──────────────────────────────────────────────────────────────────┴─────────────────────────┴────────┴────────┴─────────────┴────────────┴───────┴───────╯
```
