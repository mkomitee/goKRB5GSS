package kerberos

// #cgo LDFLAGS: -lkrb5 -lk5crypto -lcom_err
// #include <krb5.h>
import "C"

type Error struct {
	Code int
	Msg string
}

func (e Error)Error() string {
	return e.Msg
}

type Context struct {
	kctx C.krb5_context
}

func NewContext() (*Context, error) {
	var ctx C.krb5_context
	code := C.krb5_init_context(&ctx)
	if code != 0 {
		return nil, Error{
			Code: int(code),
			Msg: "Cannot initialize Kerberos Context"}
	}
	return &Context{kctx: ctx}, nil
}

func (c *Context) FreeContext() {
	if c.kctx != nil {
		C.krb5_free_context(c.kctx)
		c.kctx = nil
	}
}
