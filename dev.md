## Dev Notes

TODO:

Way more tests. I found a rough error recently that should have been easily
caught. Get coverage way up.

### Prep For Mixnet
The crux here is that I need to be able to encrypt a message with just a
public signing key.

https://github.com/golang/go/issues/20504

So I think I'll just add an xchange key until this gets done.