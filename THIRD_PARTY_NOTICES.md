# Third-party notices

iG Windows Tuner contains no third-party code. It credits the following projects whose ideas were re-implemented.

## Chris Titus Tech's Windows Utility (WinUtil)

- Project: https://github.com/ChrisTitusTech/winutil
- Version reviewed: commit `d32efebac6d50ce1a4e9734fb9400b884f76e7e6` (21 October 2026)
- License: MIT License, Copyright (c) 2022 CT Tech Group LLC

The Toolkit section and the catalog items marked `source: "winutil"` (each with an `attribution`) are inspired by WinUtil's configuration. They were re-implemented with iG Windows Tuner's own texts, Microsoft sources, Windows defaults and revert paths; no WinUtil code, text or data files are included, so nothing is vendored under `third_party/`. The item-by-item decisions are in [docs/WINUTIL_MAPPING.md](docs/WINUTIL_MAPPING.md). WinUtil is never downloaded or run by iG Windows Tuner.

MIT License text (as published by the WinUtil project):

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## winget packages

The Toolkit installs packages with winget, the Windows Package Manager, from the winget community repository. Each package is licensed by its owner; the Toolkit shows winget's agreements and passes the accept flags only after you accept them.
