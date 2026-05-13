package destinations

import "bytes"

// bytesReader wraps a byte slice in a bytes.Reader. It is a tiny
// helper used by the JSON decoder so that the file does not have to
// import bytes solely to construct a Reader.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
