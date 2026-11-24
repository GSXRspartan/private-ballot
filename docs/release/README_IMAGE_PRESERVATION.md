# README image preservation record

Recorded before and after the Hosted/Mainnet README update. No existing
picture was added, removed, renamed, relocated, replaced, or modified.

| README line reference | Image path | SHA-256 before | SHA-256 after |
|---|---|---|---|
| 23 | `docs/images/release-v0.1.0/01-home-verified-anchored.png` | `8374404887dd21ac4ddb7a33a45a98004e62fe290d785129ae8fc514857033f3` | `8374404887dd21ac4ddb7a33a45a98004e62fe290d785129ae8fc514857033f3` |
| 265 | `docs/images/release-v0.1.0/02-load-tester-100-of-100.png` | `7c23fe9b2619b2b8979c08329a33b14557e477d15e14c15b5edf1c2033cfad29` | `7c23fe9b2619b2b8979c08329a33b14557e477d15e14c15b5edf1c2033cfad29` |
| 326 (now 04-archive) | `docs/images/release-v0.1.0/04-archive-ootle-verified.png` | `f49e7d34831200de8eb5d4ba5442ed5bde8d01b3f472a3d049bad76018b1b598` | `f49e7d34831200de8eb5d4ba5442ed5bde8d01b3f472a3d049bad76018b1b598` |
| 330 (now 03-tally) | `docs/images/release-v0.1.0/03-tally-final-archive.png` | `bea0547c73dad359eef2bd0685fd19b25710b13433f876698fa6b5dc808ed2ad` | `bea0547c73dad359eef2bd0685fd19b25710b13433f876698fa6b5dc808ed2ad` |
| 341 | `docs/images/release-v0.1.0/05-ootle-canonical-payload.png` | `650acad3563ffcd67df7eba3158cfae5cf7d7f71e02d3759a6f7f0cde0921f64` | `650acad3563ffcd67df7eba3158cfae5cf7d7f71e02d3759a6f7f0cde0921f64` |

The README still contains exactly five markdown image references, and all
five resolve to the original tracked files. No new screenshot was added.
All 33 local/README link targets resolve after the edit.

Correction (2026-11-24): the recorded SHA-256 for `05-ootle-canonical-payload.png`
was missing one character. All five images remain byte-identical to their
original Git blobs from commit `851d0c2` (verified with `git hash-object` and
`git rev-parse HEAD:<path>`); only this hash record was corrected.
