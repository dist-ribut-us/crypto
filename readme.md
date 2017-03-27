## Dist-ribut-us Crypto
Wrapper around crypto functions.

[![GoDoc](https://godoc.org/github.com/dist-ribut-us/crypto?status.svg)](https://godoc.org/github.com/dist-ribut-us/crypto)

### Interrupt
A handful of functions (all related to generating cryptographic random data) can
encounter a rare error of running out of entropy. This is unlikely and
unrecoverable. The standard Go model of bubbling the error as a return value was
not useful in these cases. The error could bubble through several layers only to
have the top level panic or exit.

In place of the Go model of bubbling the error, for these functions, an
interrupt is used. If crypto encounters an error when generating random data it
will log the error and call InterruptHandler. This can be set to another
function if main needs to do some clean up before closing. The default behavior
is open a new go routine and panic (so that the panic will not interact with
recover in another package up the stack) and then block any further execution on
the original thread.

Functions that can trigger InterruptHandler:
* GenerateKey
* RandomSymmetric
* RandomNonce
* RandInt
* RandUint32
* RandUint16