# bips
Bitcoin Improvement Proposals implemented in Clojure.w

BIP39
=====

Generate 12-25 words mnemonic seed from random 128-512 bits of random data
and 512 bits seed from the mnemonic seed.

Examples
--------

```clojure
(entropy->mnemonic (codecs/hex->bytes "000102030405060708090a0b0c0d0e0f"))
```
"abandon amount liar amount expire adjust cage candy arch gather drum buyer"

```clojure
(check-mnemonic "abandon amount liar amount expire adjust cage candy arch gather drum buyer")
```
true

```clojure
(mnemonic->seed "abandon amount liar amount expire adjust cage candy arch gather drum buyer")
```
"3779b041fab425e9c0fd55846b2a03e9a388fb12784067bd8ebdb464c2574a05bcc7a8eb54d7b2a2c8420ff60f630722ea5132d28605dbc996c8ca7d7a8311c0"

Reference
---------

- https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

BIP32
=====

Multi-Account Hierarchy for Deterministic Wallets

Examples
--------

```clojure
(derive-master-node "3779b041fab425e9c0fd55846b2a03e9a388fb12784067bd8ebdb464c2574a05bcc7a8eb54d7b2a2c8420ff60f630722ea5132d28605dbc996c8ca7d7a8311c0")
```
{:private-key
 "c95cfacbafcd5f00187eac74a10f48e8a77d2efe477ae6cb84322ffb28546352",
 :public-key
 "0392030131e97b2a396691a7c1d91f6b5541649b75bda14d056797ab3cadcaf2f5",
 :chain-code
 "2f891b55b105d8c24e6f267c666ba55b7994aa14214c5aedad4b694eb7fd2d49",
 :depth 0}

```clojure
(CKDpriv {:private-key
 "c95cfacbafcd5f00187eac74a10f48e8a77d2efe477ae6cb84322ffb28546352",
 :public-key
 "0392030131e97b2a396691a7c1d91f6b5541649b75bda14d056797ab3cadcaf2f5",
 :chain-code
 "2f891b55b105d8c24e6f267c666ba55b7994aa14214c5aedad4b694eb7fd2d49",
 :depth 0} 0)
 
```
{:private-key
 "47f737c97d068f75aee135e677f2cd3e06fcf03620a211962eac715289653902",
 :chain-code
 "e20e803729e1db26fb87defdc50f07242727ad74c8765b18901493ce528d44ae",
 :index 0,
 :depth 1}

```clojure
(CKDpub {:private-key
 "c95cfacbafcd5f00187eac74a10f48e8a77d2efe477ae6cb84322ffb28546352",
 :public-key
 "0392030131e97b2a396691a7c1d91f6b5541649b75bda14d056797ab3cadcaf2f5",
 :chain-code
 "2f891b55b105d8c24e6f267c666ba55b7994aa14214c5aedad4b694eb7fd2d49",
 :depth 0} 0)
```
{:public-key
 "03d8bb162ef993171627788a4aba3adb0a149172eded1a519c62b27ea58e0e9613",
 :chain-code
 "e20e803729e1db26fb87defdc50f07242727ad74c8765b18901493ce528d44ae",
 :index 0,
 :depth 1}

```clojure
(N {:private-key
 "47f737c97d068f75aee135e677f2cd3e06fcf03620a211962eac715289653902",
 :chain-code
 "e20e803729e1db26fb87defdc50f07242727ad74c8765b18901493ce528d44ae",
 :index 0,
 :depth 1})
 ```
{:public-key
 "03d8bb162ef993171627788a4aba3adb0a149172eded1a519c62b27ea58e0e9613",
 :chain-code
 "e20e803729e1db26fb87defdc50f07242727ad74c8765b18901493ce528d44ae",
 :index 0,
 :depth 1}

```clojure
(derive-path "000102030405060708090a0b0c0d0e0f" "m/0H/1/2H/2/1000000000" :private)
```
{:private-key
 "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
 :chain-code
 "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
 :index 1000000000,
 :depth 5}

Reference
---------

- https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
