# kex | ECDH Key Exchange in Go
kex is a small wrapper around go's `crypto/elliptic` library I 
used in a personal project to further abstract and simplify shared secret generation
within an client/server configuration.

# INSTALL
```bash
go get github.com/xtrcode/kex
```

# USAGE
```go
    
alice := kex.NewP512()
bob := kex.NewP512()

alicePK, err := alice.Encode()
if err != nil {
    log.Fatal("Encoding alice' public key failed")
}

bobPK, err := bob.Encode()
if err != nil {
    log.Fatal("Encoding bobs public key failed")
}

// transmit data beep bloop

if err = bob.Decode(alicePK); err != nil {
    log.Fatal(err)
}

if err = alice.Decode(bobPK); err != nil {
    log.Fatal(err)
}

alice.Calculate()
bob.Calculate()

fmt.Printf("\nShared key (Alice) %x\n", alice.Sum224())
fmt.Printf("\nShared key (Bob)  %x\n", bob.Sum224())
```

The generated byte-sequence of `kexObj.Encode()` is encoded with `encoding/gob` and ready
for transmission. At the other end just throw the byte-sequence into `kexObj2.Decode(data)`, calculate
your shared secret and start communicating!

For an (non)official implementation see: [https://github.com/golang/crypto/blob
/e8f229864d71a49e5fdc4a9a134c5f85c4c33d64/ssh/kex.go#L210-L377](https://github.com/golang/crypto/blob/e8f229864d71a49e5fdc4a9a134c5f85c4c33d64/ssh/kex.go#L210-L377)

# FAQ
    Q: Why ECDH and not DHE?
    A: Go doesn't support DHE out-of-the box (at least to my knowledge).
    
    Q: Why don't you check the factors?
    A: Kex isn't intended for production use. Please create a pull request if you
       want to contribute additional features.
    
# LICENSE
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>