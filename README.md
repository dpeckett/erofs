# EROFS

An EROFS (Enhanced Read-Only File System) implementation for Go.

Thanks to the gVisor project for the underlying code that this project is
based on.

## Limitations

No support atm for compression or deduplication. Happy to accept PRs for this.

## Usage

```go
package main

import (
  "log"
  "os"

  "github.com/dpeckett/erofs"
)

func main() {
  f, err := os.Open("path/to/image")
  if err != nil {
    log.Fatal(err)
  }
  defer f.Close()

  image, err := erofs.OpenImage(f)
  if err != nil {
    log.Fatal(err)
  }

  fsys, err := erofs.NewFilesystem(image)
  if err != nil {
    log.Fatal(err)
  }

  // Do something with the filesystem.
}
```

## License

This project is licensed under the Mozilla Public License 2.0 - see the 
[LICENSE](LICENSE) file for details.