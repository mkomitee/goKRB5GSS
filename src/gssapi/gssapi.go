package gssapi

// #cgo LDFLAGS: -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err
// #include <gssapi.h>
// #include <gssapi/gssapi_generic.h>
// #include <gssapi/gssapi_krb5.h>
import "C"

type Error struct {
	Major, Minor int
	Msg string
}

func (e Error)Error() string {
	return e.Msg
}
