Monors: the Mono automatic merging tool for github
--------

 It is largely inspired by the [Bors](https://github.com/graydon/bors), and it is
 written for the [Mono](https://github.com/mono/mono) project, even if we can easily
 add support for other projects.

 We assume bors is run in a loop, perhaps once per minute from jenkins (or cron)
 (github has a rate-limited API). It simply work by pulling all pull requests,
 checking if they are mergeable, and the `merge` command has been issue, and merge
 it appropriately. It does not store any state, making it easy to run it from
 anywhere, at any time, without dependencies.

 The general cycle of operation is as follows:
  - load all pull requests
    - load all statuses and comments
    - check if mergeable
    - check statuses for failure/pending
    - merge

Dependencies
--------

```
pip install slacker
```

License
-------

Copyright (c) 2015 Xamarin, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
