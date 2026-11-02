# Test fixtures

`song.mp3`, `bundle.7z`, `bundle.rar`, `report.pdf` and `clip.mp4` are copied
from metakill's `testdata/fixtures` (github.com/computerguymackay/metakill,
MIT licence, same author). They carry known planted metadata, such as
"Jane Photographer", "iPhone 14 Pro" and "secret comment".

`locked.7z` is a password-protected 7z (password `PASSWORD`, encrypted
headers) made with 7-Zip, for testing that encrypted archives are refused.
